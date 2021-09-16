'''
Authenticates a user against Okta and then uses the resulting SAML assertion 
to retrieve temporary STS credentials from AWS.

Based on 
    https://github.com/jmhale/okta-awscli

While trying to use the original work I've met few issues which I'm trying to address here:
1) sometimes script would override the config file 
  (when you pick options from cmdl) and sometimes it wouldn't
2) bug reading inline comments (end of the line comment is treated as a value)
3) after installation you actually need to use it as:
  'python -m oktaawscli.okta_awscli'
4) bug when you want to pick MFA factor - it doesn't get saved and you need to continue
  picking it (but the AWS role gets saved and overrides config)
5) i don't like the default config file name and location
6) don't want to be installing modules - just want to download single script file and use it
7) some bad code (repetitions, formatting, and non-optimal solutions in some cases)
8) etc...

This is still a work in progress and I'll be doing refactoring as time allows

#TODO: - list of improvements
0) normal help
1) make sure ~/.aws/credentials exists and there is a [aws-profile] section in it..
   otherwise, the 'boto3.client('sts')' will fail
2) straighten creation of new profiles (both of oktaaws, and aws(if anyting needed to be done))
3) straighten 'print' vs. 'log' in whole script

@author: Alexandre_Griniuk
'''

import os
import sys
import time
import requests
import re
import logging
import base64
import xml.etree.ElementTree as ET
import boto3
import click
from codecs import decode
from collections import namedtuple
from configparser import RawConfigParser
from botocore.exceptions import ClientError
from getpass import getpass
from urllib.parse import parse_qs
from urllib.parse import urlparse
from bs4 import BeautifulSoup as bs
from subprocess import call


try:
    from u2flib_host import u2f, exc
    from u2flib_host.constants import APDU_WRONG_DATA
    U2F_ALLOWED = True
except ImportError:
    U2F_ALLOWED = False



#temporary here - will move somewhere else
def getParser():
    return RawConfigParser(inline_comment_prefixes="#")

#
# ------------------------------------------------------------------------
#

class AwsAuth():
    """ Methods to support AWS authentication using STS """
    
    def __init__(self, okta_auth_config, logger):
        self.logger = logger
        self.creds_dir = os.path.expanduser('~') + "/.aws"
        self.creds_file = self.creds_dir + "/credentials"
        self.profile = okta_auth_config.conf_aws_profile()
        self.duration = okta_auth_config.conf_duration()
        self.role = okta_auth_config.conf_role()

    def choose_aws_role(self, assertion):
        """ Choose AWS role from SAML assertion """

        roles = self.__extract_available_roles_from(assertion)
        if self.role:
            predefined_role = self.__find_predefiend_role_from(roles)
            if predefined_role:
                self.logger.info("Using predefined role: %s" % self.role)
                return predefined_role
            else:
                self.logger.info("""Predefined role, %s, not found in the list of roles assigned to you.""" % self.role)
                self.logger.info("Please choose a role.")

        role_options = self.__create_options_from(roles)
        for option in role_options:
            print(option)

        role_choice = int(input('Please select the AWS role: ')) - 1
        return roles[role_choice]

    def get_sts_token(self, role_arn, principal_arn, assertion):
        """ Gets a token from AWS STS """

        # Connect to the GovCloud STS endpoint if a GovCloud ARN is found.
        arn_region = principal_arn.split(':')[1]
        if arn_region == 'aws-us-gov':
            sts = boto3.client('sts', region_name='us-gov-west-1')
        else:
            sts = boto3.client('sts')

        try:
            response = sts.assume_role_with_saml(
                RoleArn=role_arn, PrincipalArn=principal_arn,
                SAMLAssertion=assertion, DurationSeconds=self.duration or 3600
            )
        except ClientError as ex:
            if self.logger:
                self.logger.error("Could not retrieve credentials: %s" % ex.response['Error']['Message'])
                exit(-1)
            else:
                raise

        credentials = response['Credentials']
        return credentials

    def check_sts_token(self):
        """ Verifies that STS credentials are valid """
        # Don't check for creds if profile is blank
        if not self.profile:
            return False

        parser = getParser()
        parser.read(self.creds_file)

        #TODO: move the checking into constructor 
        if not os.path.exists(self.creds_dir):
            self.logger.info("AWS credentials path does not exist. Not checking.")
            return False

        elif not os.path.isfile(self.creds_file):
            self.logger.info("AWS credentials file does not exist. Not checking.")
            return False

        elif not parser.has_section(self.profile):
            self.logger.info("No existing credentials found. Requesting new credentials.")
            return False

        session = boto3.Session(profile_name=self.profile)
        sts = session.client('sts')
        try:
            sts.get_caller_identity()
        except ClientError as ex:
            if ex.response['Error']['Code'] == 'ExpiredToken':
                self.logger.info("Temporary credentials have expired. Requesting new credentials.")
                return False
            else:
                #TODO: log ?
                raise

        self.logger.info("STS credentials are valid. Nothing to do.")
        return True

    def write_sts_token(self, access_key_id, secret_access_key, session_token):
        """ Writes STS auth information to credentials file """
        if not os.path.exists(self.creds_dir):
            os.makedirs(self.creds_dir)
        config = getParser()

        if os.path.isfile(self.creds_file):
            config.read(self.creds_file)

        if not config.has_section(self.profile):
            config.add_section(self.profile)

        config.set(self.profile, 'aws_access_key_id', access_key_id)
        config.set(self.profile, 'aws_secret_access_key', secret_access_key)
        config.set(self.profile, 'aws_session_token', session_token)

        with open(self.creds_file, 'w+') as configfile:
            config.write(configfile)
        self.logger.info("Temporary credentials written to profile: %s" % self.profile)
        self.logger.info("Invoke using: aws --profile %s <service> <command>" % self.profile)

    @staticmethod
    def __extract_available_roles_from(assertion):
        aws_attribute_role = 'https://aws.amazon.com/SAML/Attributes/Role'
        attribute_value_urn = '{urn:oasis:names:tc:SAML:2.0:assertion}AttributeValue'
        roles = []
        role_tuple = namedtuple("RoleTuple", ["principal_arn", "role_arn"])
        root = ET.fromstring(base64.b64decode(assertion))
        for saml2attribute in root.iter('{urn:oasis:names:tc:SAML:2.0:assertion}Attribute'):
            if saml2attribute.get('Name') == aws_attribute_role:
                for saml2attributevalue in saml2attribute.iter(attribute_value_urn):
                    roles.append(role_tuple(*saml2attributevalue.text.split(',')))
        return roles

    @staticmethod
    def __create_options_from(roles):
        options = []
        for index, role in enumerate(roles):
            options.append("%d: %s" % (index + 1, role.role_arn))
        return options

    def __find_predefiend_role_from(self, roles):
        found_roles = filter(lambda role_tuple: role_tuple.role_arn == self.role, roles)
        return next(iter(found_roles), None)



#
# ------------------------------------------------------------------------
#


 
class OktaAuthConfig():
    """ Config helper class """
    def __init__(self, okta_profile, logger):
        self.logger = logger
        self.okta_profile = "default"
        #TODO: add verification of config_dir
        self.config_dir = os.path.expanduser('~') + '/.oktaaws'
        if not os.path.exists(self.config_dir):
            os.makedirs(self.config_dir)
        self.config_file = self.config_dir + '/' + okta_profile
        self._value = getParser()
        self._value.read(self.config_file)

    def conf_base_url(self):
        """ Gets base URL from config """
        if self._value.has_option(self.okta_profile, 'base-url'):
            base_url = self._value.get(self.okta_profile, 'base-url')
            self.logger.info("Authenticating to: %s" % base_url)
        else:
            base_url = self._value.get(self.okta_profile, 'base-url')
            self.logger.info("Using base-url %s" % base_url)
        return base_url

    def conf_app_link(self):
        """ Gets app_link from config """
        app_link = None
        if self._value.has_option(self.okta_profile, 'app-link'):
            app_link = self._value.get(self.okta_profile, 'app-link')
        elif self._value.has_option(self.okta_profile, 'app-link'):
            app_link = self._value.get(self.okta_profile, 'app-link')
        self.logger.info("App Link set as: %s" % app_link)
        return app_link

    def conf_username(self):
        """ Gets username from config """
        if self._value.has_option(self.okta_profile, 'username'):
            username = self._value.get(self.okta_profile, 'username')
            self.logger.info("Authenticating as: %s" % username)
        else:
            username = input('Enter username: ')
        return username

    def conf_password(self):
        """ Gets password from config """
        if self._value.has_option(self.okta_profile, 'password'):
            password = self._value.get(self.okta_profile, 'password')
        else:
            password = getpass('Enter password: ')
        return password

    def conf_factor(self):
        """ Gets factor from config """
        if self._value.has_option(self.okta_profile, 'factor'):
            factor = self._value.get(self.okta_profile, 'factor')
            self.logger.debug("Setting MFA factor to %s" % factor)
            return factor
        return None
       
    def conf_preferred_mfa_type(self):
        """ Gets preferred-mfa-type from config """
        if self._value.has_option(self.okta_profile, 'preferred-mfa-type'):
            res = self._value.get(self.okta_profile, 'preferred-mfa-type')
            self.logger.debug("Setting Preferred MFA Type to %s" % res)
            return res
        return None

    def conf_duration(self):
        """ Gets requested duration from config, ignore it on failure """
        if self._value.has_option(self.okta_profile, 'duration'):
            duration = self._value.get(self.okta_profile, 'duration')
            self.logger.debug("Requesting a duration of %s seconds" % duration)
            try:
                return int(duration)
            except ValueError as e:
                self.logger.warn("Duration could not be converted to a number, ignoring.")
        return None
    
    def conf_role(self):
        """ Gets role from config """
        if self._value.has_option(self.okta_profile, 'role'):
            res = self._value.get(self.okta_profile, 'role')
            self.logger.debug("Setting 'role' to %s" % res)
            return res
        return None

    def conf_aws_profile(self):
        """ Gets 'aws-profile' from config """
        if self._value.has_option(self.okta_profile, 'aws-profile'):
            res = self._value.get(self.okta_profile, 'aws-profile')
            self.logger.debug("Setting 'aws-profile' to %s" % res)
            return res
        return None

    def save_chosen_role_for_profile(self, role_arn):
        """ Gets role from config """
        if not self._value.has_section(self.okta_profile):
            self._value.add_section(self.okta_profile)

        base_url = self.conf_base_url()
        self._value.set(self.okta_profile, 'base-url', base_url)
        self._value.set(self.okta_profile, 'role', role_arn)

        with open(self.config_file, 'w+') as configfile:
            self._value.write(configfile)

    def save_chosen_app_link_for_profile(self, app_link):
        """ Gets role from config """
        if not self._value.has_section(self.okta_profile):
            self._value.add_section(self.okta_profile)

        base_url = self.conf_base_url()
        self._value.set(self.okta_profile, 'base-url', base_url)
        self._value.set(self.okta_profile, 'app-link', app_link)

        with open(self.config_file, 'w+') as configfile:
            self._value.write(configfile)



#
# ------------------------------------------------------------------------
#


class OktaAuth():
    """ Handles auth to Okta and returns SAML assertion """
    def __init__(self, okta_auth_config, logger, totp_token):
        self.totp_token = totp_token
        self.logger = logger
        self.factor = ""
        self._verify_ssl_certs = True
        self._preferred_mfa_type = okta_auth_config.conf_preferred_mfa_type()
        self._mfa_code = None
        self.https_base_url = "https://%s" % okta_auth_config.conf_base_url()
        self.username = okta_auth_config.conf_username()
        self.password = okta_auth_config.conf_password()
        self.factor = okta_auth_config.conf_factor()
        self.app_link = okta_auth_config.conf_app_link()
        self.okta_auth_config = okta_auth_config
        self.session = None
        self.session_token = ""
        self.session_id = ""

    def primary_auth(self):
        """ Performs primary auth against Okta """

        auth_data = {
            "username": self.username,
            "password": self.password
        }
        self.session = requests.Session()
        resp = self.session.post(self.https_base_url + '/api/v1/authn', json=auth_data)
        resp_json = resp.json()
        self.cookies = resp.cookies
        if 'status' in resp_json:
            if resp_json['status'] == 'MFA_REQUIRED':
                factors_list = resp_json['_embedded']['factors']
                state_token = resp_json['stateToken']
                session_token = self.verify_mfa(factors_list, state_token)
            elif resp_json['status'] == 'SUCCESS':
                session_token = resp_json['sessionToken']
            elif resp_json['status'] == 'MFA_ENROLL':
                self.logger.error("MFA not enrolled. Cannot continue.\nEnroll into MFA factor in the Okta Web UI first!")
                exit(2)
        elif resp.status_code != 200:
            self.logger.error(resp_json['errorSummary'])
            exit(1)
        else:
            self.logger.error(resp_json)
            exit(1)
        return session_token

    def verify_mfa(self, factors_list, state_token):
        """ Performs MFA auth against Okta """

        supported_factor_types = ["token:software:totp", "push"]
        if U2F_ALLOWED:
            supported_factor_types.append("u2f")

        supported_factors = []
        for factor in factors_list:
            if factor['factorType'] in supported_factor_types:
                supported_factors.append(factor)
            else:
                self.logger.error("Unsupported factorType: %s" % (factor['factorType'],))

        supported_factors = sorted(
            supported_factors,
            key=lambda factor: (factor['provider'], factor['factorType'])
        )
        if len(supported_factors) == 1:
            session_token = self.verify_single_factor(supported_factors[0], state_token)
        elif len(supported_factors) > 0:
            if not self.factor:
                print("Registered MFA factors:")
            for index, factor in enumerate(supported_factors):
                factor_type = factor['factorType']
                factor_provider = factor['provider']

                if factor_provider == "GOOGLE":
                    factor_name = "Google Authenticator"
                elif factor_provider == "OKTA":
                    if factor_type == "push":
                        factor_name = "Okta Verify - Push"
                    else:
                        factor_name = "Okta Verify"
                elif factor_provider == "FIDO":
                    factor_name = "u2f"
                else:
                    factor_name = "Unsupported factor type: %s" % factor_provider

                if self.factor:
                    if self.factor == factor_provider:
                        factor_choice = index
                        self.logger.info("Using configured factor choice %d" % factor_choice)
                        break
                else:
                    print("%d: %s" % (index + 1, factor_name))
            if not self.factor:
                factor_choice = int(input('Please select the MFA factor: ')) - 1
            self.logger.info("Performing secondary authentication using: %s" % supported_factors[factor_choice]['provider'])
            session_token = self.verify_single_factor(supported_factors[factor_choice], state_token)
        else:
            print("MFA required, but no supported factors enrolled! Exiting.")
            exit(1)
        return session_token

    def verify_single_factor(self, factor, state_token):
        """ Verifies a single MFA factor """
        
        self.logger.info("verifying MFA with factor : %s" % factor)
        req_data = {"stateToken": state_token}
        if factor['factorType'] == 'token:software:totp':
            if self.totp_token:
                self.logger.info("Using TOTP token from command line arg")
                req_data['answer'] = self.totp_token
            else:
                req_data['answer'] = input('Enter MFA token: ')

        post_url = factor['_links']['verify']['href']
        resp = requests.post(post_url, json=req_data)
        resp_json = resp.json()
        if 'status' in resp_json:
            if resp_json['status'] == "SUCCESS":
                return resp_json['sessionToken']
            elif resp_json['status'] == "MFA_CHALLENGE" and factor['factorType'] !='u2f':
                print("Waiting for push verification...")
                while True:
                    resp = requests.post(resp_json['_links']['next']['href'], json=req_data)
                    resp_json = resp.json()
                    if resp_json['status'] == 'SUCCESS':
                        return resp_json['sessionToken']
                    elif resp_json['factorResult'] == 'TIMEOUT':
                        print("Verification timed out")
                        exit(1)
                    elif resp_json['factorResult'] == 'REJECTED':
                        print("Verification was rejected")
                        exit(1)
                    else:
                        time.sleep(0.5)

            if factor['factorType'] == 'u2f':
                devices = u2f.list_devices()
                if len(devices) == 0:
                    self.logger.warning("No U2F device found")
                    exit(1)

                challenge = dict()
                challenge['appId'] = resp_json['_embedded']['factor']['profile']['appId']
                challenge['version'] = resp_json['_embedded']['factor']['profile']['version']
                challenge['keyHandle'] = resp_json['_embedded']['factor']['profile']['credentialId']
                challenge['challenge'] = resp_json['_embedded']['factor']['_embedded']['challenge']['nonce']

                print("Please touch your U2F device...")
                auth_response = None
                while not auth_response:
                    for device in devices:
                        with device as dev:
                            try:
                                auth_response = u2f.authenticate(dev, challenge, resp_json['_embedded']['factor']['profile']['appId'] )
                                req_data.update(auth_response)
                                resp = requests.post(resp_json['_links']['next']['href'], json=req_data)
                                resp_json = resp.json()
                                if resp_json['status'] == 'SUCCESS':
                                    return resp_json['sessionToken']
                                elif resp_json['factorResult'] == 'TIMEOUT':
                                    self.logger.warning("Verification timed out")
                                    exit(1)
                                elif resp_json['factorResult'] == 'REJECTED':
                                    self.logger.warning("Verification was rejected")
                                    exit(1)
                            except exc.APDUError as e:
                                if e.code == APDU_WRONG_DATA:
                                    devices.remove(device)
                                time.sleep(0.1)

        elif resp.status_code != 200:
            self.logger.error(resp_json['errorSummary'])
            exit(1)
        else:
            self.logger.error(resp_json)
            exit(1)
        return None

    def get_session(self, session_token):
        """ Gets a session cookie from a session token """
        data = {"sessionToken": session_token}
        resp = self.session.post(self.https_base_url + '/api/v1/sessions', json=data).json()
        return resp['id']

    def get_apps(self, session_id):
        """ Gets apps for the user """
        sid = "sid=%s" % session_id
        headers = {'Cookie': sid}
        resp = self.session.get(self.https_base_url + '/api/v1/users/me/appLinks', headers=headers).json()
        aws_apps = []
        for app in resp:
            if app['appName'] == "amazon_aws":
                aws_apps.append(app)
        if not aws_apps:
            self.logger.error("No AWS apps are available for your user. \nExiting.")
            sys.exit(1)

        aws_apps = sorted(aws_apps, key=lambda app: app['sortOrder'])
        app_choice = 0 if len(aws_apps) == 1 else None
        if app_choice is None:
            print("Available apps:")
            for index, app in enumerate(aws_apps):
                app_name = app['label']
                print("%d: %s" % (index + 1, app_name))

            app_choice = int(input('Please select AWS app: ')) - 1
        self.logger.debug("Selected app: %s" % aws_apps[app_choice]['label'])
        return aws_apps[app_choice]['label'], aws_apps[app_choice]['linkUrl']

    def get_simple_assertion(self, html):
        soup = bs(html.text, "html.parser")
        for input_tag in soup.find_all('input'):
            if input_tag.get('name') == 'SAMLResponse':
                return input_tag.get('value')
        return None

    def get_mfa_assertion(self, html):
        soup = bs(html.text, "html.parser")
        if hasattr(soup.title, 'string') and re.match(".* - Extra Verification$", soup.title.string):
            state_token = decode(re.search(r"var stateToken = '(.*)';", html.text).group(1), "unicode-escape")
        else:
            self.logger.error("No Extra Verification")
            return None

        self.session.cookies['oktaStateToken'] = state_token
        self.session.cookies['mp_Account Settings__c'] = '0'
        self.session.cookies['Okta_Verify_Autopush_2012557501'] = 'true'
        self.session.cookies['Okta_Verify_Autopush_-610254449'] = 'true'

        api_response = self.stepup_auth(self.https_base_url + '/api/v1/authn', state_token)
        resp = self.session.get(self.app_link)

        return self.get_saml_assertion(resp)

    def get_saml_assertion(self, html):
        """ Returns the SAML assertion from HTML """
        assertion = self.get_simple_assertion(html) or self.get_mfa_assertion(html)

        if not assertion:
            self.logger.error("SAML assertion not valid: " + assertion)
            exit(-1)
        return assertion

    def stepup_auth(self, embed_link, state_token=None):
        """ Login to Okta using the Step-up authentication flow"""
        flow_state = self._get_initial_flow_state(embed_link, state_token)

        while flow_state.get('apiResponse').get('status') != 'SUCCESS':
            flow_state = self._next_login_step(flow_state.get('stateToken'), flow_state.get('apiResponse'))

        return flow_state['apiResponse']

    def _next_login_step(self, state_token, login_data):
        """ decide what the next step in the login process is"""
        if 'errorCode' in login_data:
            self.logger.error("LOGIN ERROR: %s | Error Code: %s" % (login_data['errorSummary'], login_data['errorCode']))
            exit(2)

        status = login_data['status']

        if status == 'UNAUTHENTICATED':
            self.logger.error("You are not authenticated -- please try to log in again")
            exit(2)
        elif status == 'LOCKED_OUT':
            self.logger.error("Your Okta access has been locked out due to failed login attempts.")
            exit(2)
        elif status == 'MFA_ENROLL':
            self.logger.error("You must enroll in MFA before using this tool.")
            exit(2)
        elif status == 'MFA_REQUIRED':
            return self._login_multi_factor(state_token, login_data)
        elif status == 'MFA_CHALLENGE':
            if 'factorResult' in login_data and login_data['factorResult'] == 'WAITING':
                return self._check_push_result(state_token, login_data)
            else:
                return self._login_input_mfa_challenge(state_token, login_data['_links']['next']['href'])
        else:
            raise RuntimeError('Unknown login status: ' + status)


    def _get_initial_flow_state(self, embed_link, state_token=None):
        """ Starts the authentication flow with Okta"""
        if state_token is None:
            response = self.session.get(embed_link, allow_redirects=False)
            url_parse_results = urlparse(response.headers['Location'])
            state_token = parse_qs(url_parse_results.query)['stateToken'][0]

        response = self.session.post(
            self.https_base_url + '/api/v1/authn',
            json={'stateToken': state_token},
            headers=self._get_headers(),
            verify=self._verify_ssl_certs
        )

        return {'stateToken': state_token, 'apiResponse': response.json()}

    def _get_headers(self):
        return {
            'User-Agent': 'Okta-awscli/0.0.1',
            'Accept': 'application/json',
            'Content-Type': 'application/json'
        }

    def get_assertion(self):
        """ Main method to get SAML assertion from Okta """
        self.session_token = self.primary_auth()
        self.session_id = self.get_session(self.session_token)
        if not self.app_link:
            app_name, app_link = self.get_apps(self.session_id)
            self.okta_auth_config.save_chosen_app_link_for_profile(app_link)
        else:
            app_name = None
            app_link = self.app_link
        self.session.cookies['sid'] = self.session_id
        resp = self.session.get(app_link)
        assertion = self.get_saml_assertion(resp)
        return app_name, assertion

    def _login_send_sms(self, state_token, factor):
        """ Send SMS message for second factor authentication"""
        response = self.session.post(
            factor['_links']['verify']['href'],
            json={'stateToken': state_token},
            headers=self._get_headers(),
            verify=self._verify_ssl_certs
        )

        self.logger.info("A verification code has been sent to %s" % factor['profile']['phoneNumber'])
        response_data = response.json()

        if 'stateToken' in response_data:
            return {'stateToken': response_data['stateToken'], 'apiResponse': response_data}
        if 'sessionToken' in response_data:
            return {'stateToken': None, 'sessionToken': response_data['sessionToken'], 'apiResponse': response_data}

    def _login_send_call(self, state_token, factor):
        """ Send Voice call for second factor authentication"""
        response = self.session.post(
            factor['_links']['verify']['href'],
            json={'stateToken': state_token},
            headers=self._get_headers(),
            verify=self._verify_ssl_certs
        )

        self.logger.info("You should soon receive a phone call at %s" % factor['profile']['phoneNumber'])
        response_data = response.json()

        if 'stateToken' in response_data:
            return {'stateToken': response_data['stateToken'], 'apiResponse': response_data}
        if 'sessionToken' in response_data:
            return {'stateToken': None, 'sessionToken': response_data['sessionToken'], 'apiResponse': response_data}


    def _login_send_push(self, state_token, factor):
        """ Send 'push' for the Okta Verify mobile app """
        response = self.session.post(
            factor['_links']['verify']['href'],
            json={'stateToken': state_token},
            headers=self._get_headers(),
            verify=self._verify_ssl_certs
        )

        self.logger.info("Okta Verify push sent...")
        response_data = response.json()

        if 'stateToken' in response_data:
            return {'stateToken': response_data['stateToken'], 'apiResponse': response_data}
        if 'sessionToken' in response_data:
            return {'stateToken': None, 'sessionToken': response_data['sessionToken'], 'apiResponse': response_data}

    def _login_multi_factor(self, state_token, login_data):
        """ handle multi-factor authentication with Okta"""
        
        self.logger.info("MFA required")
        factor = self._choose_factor(login_data['_embedded']['factors'])
        self.logger.info("Using MFA type '%s'" % self._build_factor_name(factor))
        
        factorType = factor['factorType']
        if factorType == 'sms':
            return self._login_send_sms(state_token, factor)
        elif factorType == 'call':
            return self._login_send_call(state_token, factor)
        elif factorType == 'token:software:totp':
            return self._login_input_mfa_challenge(state_token, factor['_links']['verify']['href'])
        elif factorType == 'token':
            return self._login_input_mfa_challenge(state_token, factor['_links']['verify']['href'])
        elif factorType == 'push':
            return self._login_send_push(state_token, factor)

    def _login_input_mfa_challenge(self, state_token, next_url):
        """ Submit verification code for SMS or TOTP authentication methods"""
        pass_code = self._mfa_code;
        if pass_code is None:
            pass_code = input("Enter verification code: ")
        response = self.session.post(
            next_url,
            json={'stateToken': state_token, 'passCode': pass_code},
            headers=self._get_headers(),
            verify=self._verify_ssl_certs
        )

        response_data = response.json()
        if 'status' in response_data and response_data['status'] == 'SUCCESS':
            if 'stateToken' in response_data:
                return {'stateToken': response_data['stateToken'], 'apiResponse': response_data}
            if 'sessionToken' in response_data:
                return {'stateToken': None, 'sessionToken': response_data['sessionToken'], 'apiResponse': response_data}
        else:
            return {'stateToken': None, 'sessionToken': None, 'apiResponse': response_data}

    def _check_push_result(self, state_token, login_data):
        """ Check Okta API to see if the push request has been responded to"""
        time.sleep(1)
        response = self.session.post(
            login_data['_links']['next']['href'],
            json={'stateToken': state_token},
            headers=self._get_headers(),
            verify=self._verify_ssl_certs
        )

        response_data = response.json()
        if 'stateToken' in response_data:
            return {'stateToken': response_data['stateToken'], 'apiResponse': response_data}
        if 'sessionToken' in response_data:
            return {'stateToken': None, 'sessionToken': response_data['sessionToken'], 'apiResponse': response_data}

    def _choose_factor(self, factors):
        """ gets a list of available authentication factors and
        asks the user to select the factor they want to use """

        # filter the factor list down to just the types specified in preferred_mfa_type
        if self._preferred_mfa_type is not None:
            factorsN = list(filter(lambda item: item['factorType'] == self._preferred_mfa_type, factors))
            if len(factorsN) == 1:
                factor = factorsN[0]
                factor_name = self._build_factor_name(factor)
                self.logger.info("Using configured '%s'" % factor['factorType'])
                return factor
        
        print("Pick a factor:")
        # print out the factors and let the user select
        for i, factor in enumerate(factors):
            factor_name = self._build_factor_name(factor)
            print('[ %d ] %s' % (i, factor_name))
        selection = input("Selection: ")

        # make sure the choice is valid
        if int(selection) > len(factors):
            self.logger.error("You made an invalid selection")
            exit(1)

        return factors[int(selection)]

    @staticmethod
    def _build_factor_name(factor):
        """ Build the display name for a MFA factor based on the factor type"""
        factorType = factor['factorType']
        if factorType == 'push':
            return "%s (%s/%s)" % (factorType, factor['profile']['deviceType'], factor['profile']['name'])
        elif factorType == 'sms':
            return "%s (%s)" % (factorType, factor['profile']['phoneNumber'])
        elif factorType == 'call':
            return "%s (%s)" % (factorType, factor['profile']['phoneNumber'])
        elif factorType == 'token:software:totp':
            return "%s (%s/%s)" % (factorType, factor['provider'], factor['profile']['credentialId'])
        elif factorType == 'token':
            return "%s (%s)" % (factorType, factor['profile']['credentialId'])
        else:
            return "%s (unknown MFA type)" % factorType




#
# ------------------------------------------------------------------------
#


#TODO: totp_token - allow overriding any config from profile
def get_credentials(aws_auth, okta_auth, logger):
    """ Gets credentials from Okta """
    
    _, assertion = okta_auth.get_assertion()
    role = aws_auth.choose_aws_role(assertion)
    principal_arn, role_arn = role
#
#    okta_auth_config.save_chosen_role_for_profile(role_arn)
#
    sts_token = aws_auth.get_sts_token(role_arn, principal_arn, assertion)
    access_key_id = sts_token['AccessKeyId']
    secret_access_key = sts_token['SecretAccessKey']
    session_token = sts_token['SessionToken']
    session_token_expiry = sts_token['Expiration']
    logger.info("Session token expires on: %s" % session_token_expiry)
    
    if not aws_auth.profile:
        logger.info("No 'aws-profile' specified. Printing creds to the screen")
        console_output(access_key_id, secret_access_key, session_token)
    else:
        logger.info("Using '%s' AWS profile." % aws_auth.profile)
        aws_auth.write_sts_token(access_key_id, secret_access_key, session_token)


def console_output(access_key_id, secret_access_key, session_token):
    """ Outputs STS credentials to console """
    print("Use these to set your environment variables:")
    exports = "\n".join([
        "export AWS_ACCESS_KEY_ID=%s" % access_key_id,
        "export AWS_SECRET_ACCESS_KEY=%s" % secret_access_key,
        "export AWS_SESSION_TOKEN=%s" % session_token
    ])
    print(exports)

    return exports


# pylint: disable=R0913
@click.command()
@click.option('-v', '--verbose', is_flag=True, help='Enables verbose mode (DEBUG)')
@click.option('-f', '--force', is_flag=True, help='Forces new STS credentials. \
Skips STS credentials validation.')
@click.option('--profile', help="Name of the Okta profile to use as ~/.oktaaws/<profile>\n")
@click.option('-t', '--token', help='TOTP token from your authenticator app')
@click.argument('awscli_args', nargs=-1, type=click.UNPROCESSED)
def main(profile, verbose, force, awscli_args, token):
    """ Authenticate to awscli using Okta """
    
    # Set up logging
    logger = logging.getLogger('oktaaws')
    logger.setLevel(logging.DEBUG) #not sure this is needed
    
    handler = logging.StreamHandler()
    handler.setFormatter(logging.Formatter('%(levelname)s - %(message)s'))
    handler.setLevel(logging.INFO)
    if verbose:
        handler.setLevel(logging.DEBUG)
    logger.addHandler(handler)

    if not profile:
        profile = "default"
    
    okta_auth_config = OktaAuthConfig(profile, logger)
    okta_auth = OktaAuth(okta_auth_config, logger, token)
    aws_auth = AwsAuth(okta_auth_config, logger)
    
    if force or not aws_auth.check_sts_token():
        if force:
            logger.info("Force option selected... getting new credentials.")
        else:
            logger.info("Looks like STS token is not good... getting new credentials.")
        get_credentials(aws_auth, okta_auth, logger)
    
    if not aws_auth.profile:
        return

    if awscli_args:
        cmdline = ['aws', '--profile', aws_auth.profile] + list(awscli_args)
        logger.info('Invoking: %s', ' '.join(cmdline))
        call(cmdline)



if __name__ == "__main__":
    # pylint: disable=E1120
    main()
    # pylint: enable=E1120


