import swamp
import argparse

ap = argparse.ArgumentParser()
ap.add_argument('-spyonweb_token', help="API token for SpyOnWeb", action="store")
args = ap.parse_args()

spyonweb_token = args.spyonweb_token
print(spyonweb_token)
test_url = "infowars.com"
test_id = "UA-6888464-2"

#### Test default urlscan
print("Testing urlscan.io by default")
Swamp = swamp.Swamp()
# Test url arg
output = Swamp.run(url=test_url)
assert len(output) > 0, "FAILURE ON DEFAULT URLSCAN WITH URL"
# Test id ard
output = Swamp.run(id=test_id)
assert len(output) > 0, "FAILURE ON DEFAULT URLSCAN WITH ID"
print("Success.\n\n")

#### Test specified urlscan
print("Testing urlscan.io by call")
Swamp = swamp.Swamp(api="urlscan")
# Test url arg
output = Swamp.run(url=test_url)
assert len(output) > 0, "FAILURE ON DEFAULT URLSCAN WITH URL"
# Test id ard
output = Swamp.run(id=test_id)
assert len(output) > 0, "FAILURE ON DEFAULT URLSCAN WITH ID"
print("Success.\n\n")

### Test spyonweb
if spyonweb_token != None:
    print("Testing SpyOnWeb")
    Swamp = swamp.Swamp(api="spyonweb",token=spyonweb_token)
    # Test url arg
    output = Swamp.run(url=test_url)
    assert len(output) > 0, "FAILURE ON DEFAULT URLSCAN WITH URL"
    # Test id ard
    output = Swamp.run(id=test_id)
    assert len(output) > 0, "FAILURE ON DEFAULT URLSCAN WITH ID"
    print("Success.\n\n")
else:
    print("SpyOnWeb api token not provided. Skipping...\n\n")
