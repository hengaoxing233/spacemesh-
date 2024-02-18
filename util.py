#!/usr/bin/env python
# -*- coding:utf-8 -*-
# File:util.py
# Time:2024/2/17 22:25
# Author: 很高兴
import configparser
import ctypes
import json
import os
import socket
from datetime import datetime, timedelta

import psutil


def 计算当前区块高度():
    reference_time = datetime(2023, 8, 11, 16, 0, 0)
    reference_block_height = 8064
    block_interval = timedelta(minutes=5)
    # 当前时间
    current_time = datetime.now()
    # 计算时间差并转换为区块数量
    time_difference = current_time - reference_time
    block_count = time_difference // block_interval

    # 计算当前时间的区块高度
    current_block_height = reference_block_height + block_count
    return str(current_block_height)

def is_port_open(port):
    try:
        # 创建一个套接字并尝试绑定到指定的端口
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(1)  # 设置超时时间
            s.bind(("127.0.0.1", port))  # 绑定到指定端口
            return True  # 绑定成功，端口未被占用
    except OSError:
        return False  # 绑定失败，端口已被占用


def read_postdata_metadata(file_path):
    with open(file_path, 'r') as json_file:
        data = json.load(json_file)
        return data

def check_file_exists(file_path):
    return os.path.exists(file_path)

def read_ini_config(file_path):
    config = configparser.ConfigParser()
    config.read(file_path)
    kernel32 = ctypes.windll.kernel32
    kernel32.SetConsoleMode(kernel32.GetStdHandle(-10), 128)
    if '挖矿' in config:
        mining_section = config['挖矿']
        port = mining_section.getint('端口', fallback='')
        p_disk_path = mining_section.get('P盘文件路径', fallback='')
        block_folder = mining_section.get('区块存放文件夹名称', fallback='')
        receive_address = mining_section.get('收款地址', fallback='')
        nonces = mining_section.getint('nonces', fallback='')
        threads = mining_section.getint('threads', fallback='')
        go_directory = mining_section.get('go目录', fallback='')
        cpuguaji = mining_section.get('CPU挂机', fallback='')
        return {
            '端口': port,
            'P盘文件路径': p_disk_path,
            '区块存放文件夹名称': block_folder,
            '收款地址': receive_address,
            'nonces': nonces,
            'threads': threads,
            'go目录': go_directory,
            'CPU挂机': cpuguaji,
        }
    else:
        return None

def count_unique_ips(process_id):
    try:
        connections = psutil.net_connections(kind='inet')
        unique_ips = set()

        for conn in connections:
            if conn.pid == process_id and conn.raddr:
                remote_ip = conn.raddr.ip
                unique_ips.add(remote_ip)

        return len(unique_ips)
    except psutil.NoSuchProcess:
        return 0