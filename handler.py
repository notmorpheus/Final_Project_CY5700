#!/usr/bin/python3
import subprocess
import time
import yaml
import requests
import json
import platform
from signal import signal, SIGINT
from sys import exit

timer = 6
CONFIG_PATH = 'config.yaml'
def load_config() :
    with open(CONFIG_PATH, "r") as f:
        config = yaml.safe_load(f.read())["config"]
    return config
    
config=load_config()
secret_key=config["secret"]
API_ENDPOINT='https://ipqualityscore.com/api/json/ip/{}'.format(secret_key)

#adjustable metrics
fraud_score_sensitivity = 75
ISP_Exceptions = ['Linode', 'Cloudflare']
hostname = platform.node()
command = 'bpftrace trace_outbound_connections.bt'.split()

#score weights
f_lower = 5
f_upper = 10
ta_lower = 1
ta_upper = 5
tc_lower = 1
tc_upper = 2
sc_lower = 10
sc_upper = 20


def sig_handler(signal_received, frame):
    print('SIGINT or CTRL-C detected. Exiting gracefully')
    exit(0)

def run_program(command):
    p = subprocess.Popen(command,
                         stdout=subprocess.PIPE,
                         stderr=subprocess.STDOUT)

    return iter(p.stdout.readline, b'')

def perform_iplookup(API_ENDPOINT, ipaddress):
    final_endpoint=API_ENDPOINT+'/{}'.format(ipaddress)
    response = requests.get(final_endpoint)
    response_dict=response.json()
    return response_dict

def profile_data(text):
    decoded_text=text.decode('utf-8')
    arguments = decoded_text.split()
    if arguments[0].startswith("Attaching"):
        pass
    elif len(arguments) == 4:
        process_id = int(arguments[0])
        process_name = arguments[1]
        process_ip = arguments[2]
        process_port = int(arguments[3])
        profile_list=[process_id, process_name, process_ip, process_port]

        ip_stats=perform_iplookup(API_ENDPOINT, process_ip)
        ip_reputation = ip_stats['fraud_score']
        isp = ip_stats['ISP']

        if ip_reputation>=fraud_score_sensitivity and isp not in ISP_Exceptions:
            profile_list.append(ip_reputation)
            return profile_list

def check_files_opened(process_id):
    global timer
    count=0
    timestamp = int(time.time())
    now = 0
    bpf_string= f"tracepoint:syscalls:sys_enter_openat /ppid == {process_id}"
    end_string = r"""/ { @[pid, comm] = count(); }"""
    final_string = bpf_string+end_string
    check_files_opened = subprocess.Popen(["bpftrace","-e",final_string],
                         stdout=subprocess.PIPE,
                         stderr=subprocess.STDOUT,
                         universal_newlines=True)
    print("waiting for a few seconds to collect files opened data...")
    
    time.sleep(timer+2)
    now = int(time.time())
    age = now-timestamp
    if (age>=timer):
        check_files_opened.send_signal(SIGINT)   # send Ctrl-C signal
        stdout, stderr = check_files_opened.communicate()
        if stdout is not None:
            stdout_list = stdout.split()
            element = stdout_list[-1]
            if element.isdigit():
                count = int(element)
                return count
    return count

def check_tcp_accept(process_id):
    global timer
    timestamp = int(time.time())
    count = 0
    now = 0
    bpf_string= f"tracepoint:syscalls:sys_enter_accept* /pid == {process_id}"
    end_string = r"""/ { @[pid, comm] = count(); }"""
    final_string = bpf_string+end_string
    count_tcp_accepts = subprocess.Popen(["bpftrace","-e",final_string],
                         stdout=subprocess.PIPE,
                         stderr=subprocess.STDOUT,
                         universal_newlines=True)
    time.sleep(timer+2)
    now = int(time.time())
    age = now-timestamp
    if (age>=timer):
        count_tcp_accepts.send_signal(SIGINT)   # send Ctrl-C signal
        stdout, stderr = count_tcp_accepts.communicate()
        if stdout is not None:
            stdout_list = stdout.split()
            element = stdout_list[-1]
            if element.isdigit():
                count = int(element)
                return count
    return count


def check_tcp_connect(process_id):
    global timer
    timestamp = int(time.time())
    count = 0
    now = 0
    bpf_string= f"tracepoint:syscalls:sys_enter_connect /pid == {process_id}"
    end_string = r"""/ { @[pid, comm] = count(); }"""
    final_string = bpf_string+end_string
    check_tcp_connect = subprocess.Popen(["bpftrace","-e",final_string],
                         stdout=subprocess.PIPE,
                         stderr=subprocess.STDOUT,
                         universal_newlines=True)
    time.sleep(timer+2)
    now = int(time.time())
    age = now-timestamp
    if (age>=timer):
        check_tcp_connect.send_signal(SIGINT)   # send Ctrl-C signal
        stdout, stderr = check_tcp_connect.communicate()
        if stdout is not None:
            stdout_list = stdout.split()
            element = stdout_list[-1]
            if element.isdigit():
                count = int(element)
                return count
    return count

def check_system_calls(process_id):
    global timer
    timestamp = int(time.time())
    count = 0
    now = 0
    bpf_string= f"tracepoint:raw_syscalls:sys_enter /pid == {process_id}"
    end_string = r"""/ { @[comm] = count(); }"""
    final_string = bpf_string+end_string
    count_syscalls = subprocess.Popen(["bpftrace","-e",final_string],
                         stdout=subprocess.PIPE,
                         stderr=subprocess.STDOUT,
                         universal_newlines=True)
    time.sleep(timer+2)
    now = int(time.time())
    age = now-timestamp
    if (age>=timer):
        count_syscalls.send_signal(SIGINT)   # send Ctrl-C signal
        stdout, stderr = count_syscalls.communicate()
        if stdout is not None:
            stdout_list = stdout.split()
            element = stdout_list[-1]
            if element.isdigit():
                count = int(element)
                return count
    return count   

def generate_score(files_opened,tcp_connections_accpeted,tcp_connections_made,system_calls_made):
    global f_lower, f_upper, ta_lower, ta_upper, tc_lower, tc_upper, sc_lower, sc_upper
    score = 0
    f=0
    ta=0
    tc=0
    sc=0
    if files_opened>f_lower and files_opened<=f_upper:
        f=10
    if files_opened>(f_upper+1):
        f=30
    if tcp_connections_accpeted>ta_lower and tcp_connections_accpeted<=ta_upper:
        ta=5
    if tcp_connections_accpeted>(ta_upper+1):
        ta=20
    if tcp_connections_made>tc_lower and tcp_connections_made<=tc_upper:
        tc=10
    if tcp_connections_made>(tc_upper+1):
        tc=30
    if system_calls_made>sc_lower and system_calls_made<=sc_upper:
        sc=10
    if system_calls_made>(sc_upper+1):
        sc=20
    
    score = f+ta+tc+sc
    return score
    
    
    
def determine_botnet(score):
    pass

if __name__=='__main__':
    signal(SIGINT, sig_handler)

    for line in run_program(command):
        profiled_data_list = profile_data(line)
        if(profiled_data_list is not None):
            print(f"New outbound connection detected: Process ID: {profiled_data_list[0]} Name: {profiled_data_list[1]} Destination IP Address: {profiled_data_list[2]} Desitnation Port: {profiled_data_list[3]} Reputation score: {profiled_data_list[4]} \n performing analysis on the file...")
            #pid = int(profiled_data_list[0])
            sample_pid = 17554
            files_opened = check_files_opened(sample_pid)
            tcp_connections_accpeted = check_tcp_accept(sample_pid)
            tcp_connections_made = check_tcp_connect(sample_pid)
            system_calls_made = check_system_calls(sample_pid)
            final_score = generate_score(files_opened,tcp_connections_accpeted,tcp_connections_made,system_calls_made)
            print(f"Process made the following numbers Final score is:{final_score} Process metrics identified: \n  Files Opened: {files_opened} \n TCP Connections Accpeted: {tcp_connections_accpeted} \n TCP Connections Made: {tcp_connections_made} \n System Calls Made: {system_calls_made}")
