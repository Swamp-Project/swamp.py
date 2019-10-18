import swamp
import argparse

ap = argparse.ArgumentParser()
ap.add_argument('-spyonweb_token',action="store")
args = ap.parse_args()

test_id = "UA-6888464-2"
test_url = "infowars.com"
spyonweb_token = args.spyonweb_token

print("Testing urlscan.io (default)")
Swamp = swamp.Swamp()
output = Swamp.run(id=test_id)
assert len(output) > 0, "FAILED ON URLSCAN (default) WITH ID"
output = Swamp.run(url=test_url)
assert len(output) > 0, "FAILED ON URLSCAN (default) WITH URL"
print("SUCCESS.\n\n")

print("Testing urlscan.io (explicit call)")
Swamp = swamp.Swamp(api="urlscan")
output = Swamp.run(id=test_id)
assert len(output) > 0, "FAILED ON URLSCAN (explicit) WITH ID"
output = Swamp.run(url=test_url)
assert len(output) > 0, "FAILED ON URLSCAN (explicit) WITH URL"
print("SUCCESS.\n\n")

if spyonweb_token == None:
    print("No SpyOnWeb Token given. Skipping...\n")
else:
    print("Testing SpyOnWeb")
    Swamp = swamp.Swamp(api="spyonweb",token=spyonweb_token)
    output = Swamp.run(id=test_id)
    assert len(output) > 0, "FAILED ON SPYONWEB WITH ID"
    output = Swamp.run(url=test_url)
    assert len(output) > 0, "FAILED ON SPYONWEB WITH URL"
    print("SUCCESS.\n\n")

