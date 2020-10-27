#!/usr/bin/env python3

import argparse
import json
import yaml

if __name__ == "__main__":
    # Parse the command line arguments
    parser = argparse.ArgumentParser()
    parser.add_argument("config_file", help="Config file")
    args = parser.parse_args()
    
    # Read in the config file that defines state transitions and dump it to
    # sdtout in yaml format
    with open(args.config_file) as f:
        config = json.loads(f.read())
        print(yaml.dump(config, default_flow_style=False, explicit_start=True))
