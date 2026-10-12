# TEMPORARY (#287 debug): print each SIGKILL sent by an rpc_callbacks process,
# with the frames that matter.
import re, sys
text = open(sys.argv[1], errors="replace").read()
for rec in text.split("==== ")[1:]:
    lines = rec.splitlines()
    if not any("rpc_callbacks" in l for l in lines):
        continue
    print("==== " + lines[0])
    for l in lines[1:]:
        if re.search(r"rutis|rpc_callbacks|tokio|std::process|kill", l):
            print("   " + re.sub(r"\s+", " ", l.strip())[:220])
