#!/bin/bash

function toolsCheck(){
    echo ""
    echo "Checking all the prerequisite tools"
    if [ -x "$(which s3scanner)" ] ; then
        echo "s3scanner ✔️"
    else
        echo "Could not find s3scanner, please install it with pip" >&2
        echo "If you are on *nix then run this command: pip3 install s3scanner"
        exit
    fi
    echo "This s3 is vulnerable." > abhiunix_poc.html
}
#toolsCheck

function isBucketExist(){
    
    tempValue=""
    echo ""
    echo "Checking if the bucket $line exists."

    tempValue=$(curl -X HEAD flaws.cloud.s3.amazonaws.com -I --silent | grep 200);
    
    if [[ $tempValue == *"200"* ]]; then
        echo -e "\033[31mThe $line bucket exists\033[m"
    else 
        echo "s3scanner Test Pass."
    fi
    tempValue=""
}
# #isBucketExist


function scaningWiths3scanner(){
    echo "Scanning with s3scanner, it can take time sit back and relax."

    while read -r line;
    echo -e "Scanning with s3scanner on \033[31m$line\033[m"
        do 
            tempValue=""
            echo ""

            tempValue=$(s3scanner scan -b $line | tee temp ; cat ./temp | grep -E "Read|Write|ReadACP|WriteACP|FullControl"; rm temp);
            
            if [[ $tempValue == *"Read"* || $tempValue == *"Write"* || $tempValue == *"ReadACP"* || $tempValue == *"WriteACP"* || $tempValue == *"FullControl"* ]]; then
                echo -e "\033[31mThe $line bucket is vulnerable and need immediate attention.\033[m"
                curl -X POST -H 'Content-type: application/json' --data "{'text':'The $line bucket is vulnerable and need immediate attention.'}" https://hooks.slack.com/services/webhook_URL -silent -o /dev/null
                echo "$line" >> ohoVulnerable.txt 
            else 
                echo "Test-0 Pass for $line"
            fi
            tempValue=""
        done < alls3.txt
    
    echo "Scanning with s3scanner completed."
}

function manualScans(){
    while read -r line;
     do 
        echo ""
        echo -e "Checking \033[31m$line\033[m";
        echo ""
        function checkingWriteAccess(){
            echo "Checking for WRITE Access on $line"
        tempValue=$(aws s3 cp abhiunix_poc.html s3://$line/security_test/ --no-sign-request 2> temp; cat ./temp | grep AccessDenied; rm temp); #change the directory after debugging.
        if [[ $tempValue == *"upload: ./abhiunix_poc.html to s3://"* ]]; then
            echo -e "\033[31mThe $line bucket has WRITE/DELETE access. Need immediate attention. Checkout case-1.\033[m"
            curl -X POST -H 'Content-type: application/json' --data "{'text':'The $line bucket has WRITE/DELETE access. Check out Case-1.'}" https://hooks.slack.com/services/webhook_URL -silent -o /dev/null
            echo "$line" >> ohoVulnerable.txt 
        else 
            echo "Manual Test-1 Pass"
        fi
        tempValue=""

        tempValue=$(aws s3 cp abhiunix_poc.html s3://$line/ 2> temp; cat ./temp | grep AccessDenied; rm temp);
        if [[ $tempValue == *"upload: ./abhiunix_poc.html to s3://"* ]]; then
            echo -e "\033[31mThe $line bucket has WRITE/DELETE access. Need immediate attention. Checkout case-2.\033[m"
            curl -X POST -H 'Content-type: application/json' --data "{'text':'The $line bucket has WRITE/DELETE access. Check out Case-2.'}" https://hooks.slack.com/services/webhook_URL -silent -o /dev/null
            echo "$line" >> ohoVulnerable.txt 
        else 
            echo "Manual Test-2 Pass"
        fi
        tempValue=""

        tempValue=$(aws s3 cp abhiunix_poc.html s3://$line --profile=test 2> temp; cat ./temp | grep InvalidAccessKeyId; rm temp);
        if [[ $tempValue == *"upload: ./abhiunix_poc.html to s3://"* ]]; then
            echo -e "\033[31mThe $line bucket has WRITE/DELETE access. Need immediate attention. Checkout case-3.\033[m"
            curl -X POST -H 'Content-type: application/json' --data "{'text':'The $line bucket has WRITE/DELETE access. Check out Case-3.'}" https://hooks.slack.com/services/webhook_URL -silent -o /dev/null
            echo "$line" >> ohoVulnerable.txt 
        else 
            echo "Manual Test-3 Pass"
        fi
        tempValue=""

        tempValue=$(aws s3 cp abhiunix_poc.html s3://$line --profile=labs 2> temp; cat ./temp | grep AccessDenied; rm temp);
        if [[ $tempValue == *"upload: ./abhiunix_poc.html to s3://"* ]]; then
            echo -e "\033[31mThe $line bucket has WRITE/DELETE access. Need immediate attention. Checkout case-4.\033[m"
            curl -X POST -H 'Content-type: application/json' --data "{'text':'The $line bucket has WRITE/DELETE access. Check out Case-4.'}" https://hooks.slack.com/services/webhook_URL -silent -o /dev/null
            echo "$line" >> ohoVulnerable.txt 
        else 
            echo "Manual Test-4 Pass"
        fi
        tempValue=""
        }
#
        function checkingReadAccess(){
            echo ""
            echo "Checking for Read Access on $line"
            tempValue=$(aws s3 ls s3://$line --no-sign-request 2> temp; cat ./temp | grep -E "AccessDenied|NoSuchBucket|InvalidAccessKeyId|IllegalLocationConstraintException"; rm temp);
            if [[ $tempValue == *"Access Denied"* || $tempValue == *"NoSuchBucket"* || $tempValue == *"InvalidAccessKeyId"* || $tempValue == *"IllegalLocationConstraintException"* ]]; then
                echo "Manual Test-5 Pass"
            else 
                echo -e "\033[31mThe $line bucket has READ access. Check out Case-5.\033[m"
                curl -X POST -H 'Content-type: application/json' --data "{'text':'The $line bucket has READ access. Check out Case-5.'}" https://hooks.slack.com/services/webhook_URL -silent -o /dev/null
                echo "$line" >> ohoVulnerable.txt 
            fi
            tempValue=""

            tempValue=$(aws s3 ls s3://$line 2> temp; cat ./temp | grep -E "AccessDenied|NoSuchBucket|InvalidAccessKeyId|IllegalLocationConstraintException"; rm temp);
            if [[ $tempValue == *"Access Denied"* || $tempValue == *"NoSuchBucket"* || $tempValue == *"InvalidAccessKeyId"* || $tempValue == *"IllegalLocationConstraintException"* ]]; then
                echo "Manual Test-6 Pass"
            else 
                echo -e "\033[31mThe $line bucket has READ access. Check out Case-6.\033[m"
                curl -X POST -H 'Content-type: application/json' --data "{'text':'The $line bucket has READ access. Check out Case-6.'}" https://hooks.slack.com/services/webhook_URL -silent -o /dev/null
                echo "$line" >> ohoVulnerable.txt 
            fi
            tempValue=""

            tempValue=$(aws s3 ls s3://$line --profile=test 2> temp; cat ./temp | grep -E "AccessDenied|NoSuchBucket|InvalidAccessKeyId|IllegalLocationConstraintException"; rm temp);
            if [[ $tempValue == *"Access Denied"* || $tempValue == *"NoSuchBucket"* || $tempValue == *"InvalidAccessKeyId"* || $tempValue == *"IllegalLocationConstraintException"* ]]; then
                echo "Manual Test-7 Pass"
            else 
                echo -e "\033[31mThe $line bucket has READ access. Check out Case-7.\033[m"
                curl -X POST -H 'Content-type: application/json' --data "{'text':'The $line bucket has READ access. Check out Case-7.'}" https://hooks.slack.com/services/webhook_URL -silent -o /dev/null
                echo "$line" >> ohoVulnerable.txt 
            fi
            tempValue=""

            tempValue=$(aws s3 ls s3://$line --profile=labs 2> temp; cat ./temp | grep -E "AccessDenied|NoSuchBucket|InvalidAccessKeyId|IllegalLocationConstraintException"; rm temp);
            if [[ $tempValue == *"Access Denied"* || $tempValue == *"NoSuchBucket"* || $tempValue == *"InvalidAccessKeyId"* || $tempValue == *"IllegalLocationConstraintException"* ]]; then
                echo "Manual Test-8 Pass"
            else 
                echo -e "\033[31mThe $line bucket has READ access. Check out Case-8.\033[m"
                curl -X POST -H 'Content-type: application/json' --data "{'text':'The $line bucket has READ access. Check out Case-8.'}" https://hooks.slack.com/services/webhook_URL -silent -o /dev/null
                echo "$line" >> ohoVulnerable.txt 
            fi
            tempValue=""
        }

        checkingWriteAccess
        checkingReadAccess
        done < alls3.txt
}

scaningWiths3scanner
manualScans


#while read -r line; do echo $line\n; aws s3 cp test.txt s3://asd --region=$line --profile=labs; done <regions_code.txt
