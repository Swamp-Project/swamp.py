#!/bin/bash
test_id=UA-6888464-2
test_url=infowars.com
spyonweb_token=$1

echo "Testing urlscan.io by -id"
python swamp.py -id $test_id

echo
echo "Testing urlscan.io by -url"
python swamp.py -url $test_url

echo
echo "Testing urlscan.io (specify) by -id"
python swamp.py -urlscan -id $test_id


if [ -z "$spyonweb_token" ]; then
	echo "No SpyOnWeb token given."
else
	echo
	echo "Testing SpyOnWeb by -id"
	python swamp.py -id $test_id -spyonweb -token $spyonweb_token

	echo
	echo "Testing SpyOnWeb by -url"
	python swamp.py -url $test_url -spyonweb -token $spyonweb_token
fi
