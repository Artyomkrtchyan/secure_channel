#!/bin/bash
# cleanup.sh - remove all namespaces
for n in pc1 dev1 mitm dev2 pc2; do ip netns del $n 2>/dev/null; done
echo "Cleaning is finished."
