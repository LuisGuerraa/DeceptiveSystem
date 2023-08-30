#!/bin/bash


docker cp /home/sdn/Desktop/plans_config/ containernet:containernet
docker cp /home/sdn/Desktop/deception_generator.py containernet:containernet #docker cp /home/sdn/Desktop/deception_generator_new.py containernet:containernet 
docker cp /home/sdn/Desktop/static_deception_planner.py containernet:containernet

