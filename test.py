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
print(output['urlscan'])
assert len(output['urlscan']) > 0, "FAILED ON URLSCAN (default) WITH ID"
output = Swamp.run(url=test_url)
print(output['UA-6888464-2']['urlscan'])
assert len(output['UA-6888464-2']['urlscan']) > 0, "FAILED ON URLSCAN (default) WITH URL"
print("SUCCESS.\n\n")

print("Testing urlscan.io (explicit call)")
Swamp = swamp.Swamp(api="urlscan")
output = Swamp.run(id=test_id)
print(output['urlscan'])
assert len(output['urlscan']) > 0, "FAILED ON URLSCAN (explicit) WITH ID"
output = Swamp.run(url=test_url)
print(output['UA-6888464-2']['urlscan'])
assert len(output['UA-6888464-2']['urlscan']) > 0, "FAILED ON URLSCAN (explicit) WITH URL"
print("SUCCESS.\n\n")

if spyonweb_token == None:
    print("No SpyOnWeb Token given. Skipping...\n")
else:
    print("Testing SpyOnWeb")
    Swamp = swamp.Swamp(api="spyonweb",token=spyonweb_token)
    output = Swamp.run(id=test_id)
    print(output['spyonweb'])
    assert len(output['spyonweb']) > 0, "FAILED ON SPYONWEB WITH ID"
    output = Swamp.run(url=test_url)
    print(output['UA-6888464-2']['spyonweb'])
    assert len(output['UA-6888464-2']['spyonweb']) > 0, "FAILED ON SPYONWEB WITH URL"
    print("SUCCESS.\n\n")

    print("Testing Both through 'all'")
    Swamp = swamp.Swamp(api="all",token=spyonweb_token)
    output = Swamp.run(id=test_id)
    print(output['spyonweb'])
    assert len(output['spyonweb']) > 0, "FAILED ON SPYONWEB WITH ID"
    print(output['urlscan'])
    assert len(output['urlscan']) > 0, "FAILED ON URLSCAN WITH ID"
    output = Swamp.run(url=test_url)
    print(output['UA-6888464-2']['spyonweb'])
    assert len(output['UA-6888464-2']['spyonweb']) > 0, "FAILED ON SPYONWEB WITH URL"
    print(output['UA-6888464-2']['urlscan'])
    assert len(output['UA-6888464-2']['urlscan']) > 0, "FAILED ON URLSCAN WITH URL"
    print("SUCCESS.\n\n")

    print("Testing Both through list")
    Swamp = swamp.Swamp(api=['urlscan','spyonweb'],token=spyonweb_token)
    output = Swamp.run(id=test_id)
    print(output['spyonweb'])
    assert len(output['spyonweb']) > 0, "FAILED ON SPYONWEB WITH ID"
    print(output['urlscan'])
    assert len(output['urlscan']) > 0, "FAILED ON URLSCAN WITH ID"
    output = Swamp.run(url=test_url)
    print(output['UA-6888464-2']['spyonweb'])
    assert len(output['UA-6888464-2']['spyonweb']) > 0, "FAILED ON SPYONWEB WITH URL"
    print(output['UA-6888464-2']['urlscan'])
    assert len(output['UA-6888464-2']['urlscan']) > 0, "FAILED ON URLSCAN WITH URL"
    print("SUCCESS.\n\n")



