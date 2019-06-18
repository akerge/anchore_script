#!/bin/bash

echo "Number of yet to be analyzed images:"
anchore-cli image list | grep -c not_analyzed
