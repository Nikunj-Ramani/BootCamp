folder_path="test-nikunj/folders"

ERROR=$(aws s3 ls ${folder_path} 2>&1 >/dev/null)
RC=$?

if [ $RC -eq 0 ]; then
    echo "Prefix bucket exists and please remove to avoid conflict"
    aws s3 rm $folder_path --recursive
else
    if [ -z "$ERROR" ] || [ $RC -eq 1 ]; then
        echo "Prefix bucket is not exists, it is expecting for every new process"
    else
        echo "Error: some previous folders or bucket itself is not avaialble $ERROR"
        exit 1
    fi
fi
