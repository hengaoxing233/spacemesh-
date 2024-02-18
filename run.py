#!/usr/bin/env python
# -*- coding:utf-8 -*-
# File:run.py
# Time:2024/2/17 22:21
# Author: 很高兴
import json
import logging
import os
import re
import subprocess
import psutil
import shlex
import sys
import threading
import time
from datetime import datetime
import configparser
from util import check_file_exists, read_postdata_metadata, is_port_open, read_ini_config, \
    计算当前区块高度, count_unique_ips

集_p2pnum = 0
集_pid = 0
P盘文件路径 = ''
收款地址 = ''
集_当前状态 = ''
集_奖励块状态 = ''
集_当前高度 = '0'
app_directory = ''
soft_name = 'spacemesh一机多挂 v1.5.4 作者: 很高兴 推特: hengaoxing1023'

class CommandExecutionException(Exception):
    def __init__(self, command: str, exit_code: int) -> None:
        super().__init__(f"command executed fail with exit-code={exit_code}: {command}")


_logger = logging.getLogger(__name__)
_logger_trans = {
        "DEBUG": "DBG",
        "INFO": "INF",
        "WARNING": "WAR",
        "CRITICAL": "ERR"
    }
_old_factory = logging.getLogRecordFactory()


def factory(name, level, fn, lno, msg, args, exc_info, func=None, sinfo=None, **kwargs) -> logging.LogRecord:
    record = _old_factory(name, level, fn, lno, msg, args, exc_info, func, sinfo, **kwargs)
    record.shortlevelname = _logger_trans[record.levelname]
    return record


logging.setLogRecordFactory(factory)
logging.basicConfig(
    level=logging.DEBUG,
    format=f'[{soft_name} %(shortlevelname)s] %(message)s'
)

def setTilet():
    global P盘文件路径, 收款地址, 集_当前高度, 集_当前状态, 集_奖励块状态, 集_pid, 集_p2pnum
    title = P盘文件路径.replace('\\',
                                '\\\\') + '  ' + 收款地址[
                                                 -4:] + '  ' + ' 验证层:' + str(
        集_当前高度) + '/' + str(
        计算当前区块高度()) + '  ' + 集_当前状态 + 集_奖励块状态 + ' PID:' + str(
        集_pid) + ' P2P连接数:' + str(集_p2pnum)
    os.system(f"title {title}")


class TextReadLineThread(threading.Thread):
    def __init__(self, readline, callback, *args, **kargs) -> None:
        super().__init__(*args, **kargs)
        self.readline = readline
        self.callback = callback

    def run(self):
        global 集_当前高度, 集_当前状态, 集_奖励块状态, 收款地址, 集_p2pnum, 集_pid, P盘文件路径, app_directory
        for line in iter(self.readline, ""):
            if len(line) == 0:
                break
            self.callback(line)
            # 目标日志标识列表
            target_log_identifiers = [
                "proposal eligibility for an epoch",
                "proposal eligibilities for an epoch",
                "proving: generated proof",
                "starting post verifier",
                "loaded bootstrap file",
                "post setup completed",
                "generating proof with PoW flags",
                "challenge submitted to poet proving service",
                "waiting till poet round end",
                "waiting until poet round end",
                "consensus results",
                "awaiting atx publication epoch",
                "atx published",
                "new block",
                "executed block",
                "Failed to generate proof",
                "cache warmup",
            ]

            # 使用正则表达式来匹配时间戳、日志级别等，以及目标标识和JSON数据
            log_pattern = re.compile(r'(\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}\+\d{4})\s+(\w+)\s+([\w\.]+)\s+(.*)')

            # 匹配日志行
            match = log_pattern.match(line)
            if match:
                timestamp, log_level, module, log_data = match.groups()
                # 检查是否有任何目标标识匹配当前日志行
                for target_log_identifier in target_log_identifiers:
                    if target_log_identifier in log_data:
                        json_start = log_data.find(target_log_identifier) + len(target_log_identifier)
                        json_data = log_data[json_start:].strip()
                        # 尝试解析 JSON 数据
                        try:

                            if target_log_identifier == "consensus results" or target_log_identifier == "new block":
                                json_object = json.loads(json_data)
                                layer_id = json_object['layer_id']
                                if layer_id != '':
                                    集_当前高度 = str(layer_id)
                            elif target_log_identifier == 'cache warmup':
                                集_当前状态 = '【开始预热缓存】'
                            elif target_log_identifier == "executed block":
                                json_object = json.loads(json_data)
                                try:
                                    layer_id = json_object['lid']
                                except Exception:
                                    layer_id = json_object['layer_id']
                                if layer_id != '':
                                    集_当前高度 = str(layer_id)
                            elif target_log_identifier == 'waiting till poet round end' or target_log_identifier == 'waiting until poet round end':
                                集_当前状态 = '【等待二次扫盘】'
                            elif target_log_identifier == 'challenge submitted to poet proving service':
                                集_当前状态 = '【正在提交证明】'
                            elif target_log_identifier == 'Failed to generate proof':
                                集_当前状态 = '【计算出错】'
                            elif target_log_identifier == 'generating proof with PoW flags':
                                集_当前状态 = '【正在计算并扫盘】'
                                timestr = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
                                os.path.dirname(os.path.realpath(sys.argv[0]))
                                app_directory = os.path.dirname(os.path.realpath(sys.argv[0]))
                                with open(os.path.join(app_directory, "calctime.txt"), "a") as time_file:
                                    time_file.write(P盘文件路径.replace('\\',
                                                                        '\\\\') + ' ' + timestr + '\n')
                            elif target_log_identifier == 'post setup completed':
                                集_当前状态 = '【POST完成】'
                            elif target_log_identifier == 'loaded bootstrap file':
                                集_当前状态 = '【正在加载引导文件】'
                            elif target_log_identifier == 'starting post verifier':
                                集_当前状态 = '【开始启动POST】'
                            elif target_log_identifier == 'proving: generated proof':
                                集_当前状态 = '【扫盘完毕】'
                                timestr = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
                                os.path.dirname(os.path.realpath(sys.argv[0]))
                                app_directory = os.path.dirname(os.path.realpath(sys.argv[0]))
                                with open(os.path.join(app_directory, "FoundProof.txt"), "a") as time_file:
                                    time_file.write(P盘文件路径.replace('\\', '\\\\') + ' ' + timestr + '\n')
                            elif target_log_identifier == 'awaiting atx publication epoch':
                                集_当前状态 = '【等待激活】'
                            elif target_log_identifier == 'atx published':
                                集_当前状态 = '【已激活,等待下一个纪元】'
                            elif target_log_identifier == 'proposal eligibility for an epoch':
                                # {"node_id": "1e2903b81bfa81bd624fb19cb12a74288b9c99ab3a49439eb8bbff4605e02d3f", "module": "proposalBuilder", "epoch": 7, "beacon": "0xea2f1811", "atx": "f378513b25", "weight": 259112, "ref": "6c6b3d00fc", "prev": 28243, "slots": 6, "eligible": 6, "eligible by layer": [{"layer": 28243, "slots": 1}, {"layer": 29112, "slots": 1}, {"layer": 29534, "slots": 1}, {"layer": 31068, "slots": 1}, {"layer": 31168, "slots": 1}, {"layer": 31578, "slots": 1}], "name": "proposalBuilder"}

                                json_object = json.loads(json_data)
                                # 从"layers to num proposals"中提取层的列表
                                eligible_layers = [
                                    entry["layer"] for entry in json_object["layers to num proposals"]
                                ]
                                config = configparser.ConfigParser()
                                config.add_section(收款地址)
                                rewards = f"Eligible for rewards in layers {', '.join(map(str, eligible_layers))}"
                                epoch = json_object["epoch"]
                                集_奖励块状态 = '【已出现' + str(epoch) + '纪元奖励块】'
                                config.set(收款地址, 'block', rewards)
                                try:
                                    with open(os.path.join(app_directory, "奖励块.ini"), "w") as file:
                                        config.write(file)
                                        集_奖励块状态 = '【已保存' + str(epoch) + '纪元奖励块】'
                                except Exception as e:
                                    pass
                            elif target_log_identifier == 'proposal eligibilities for an epoch':
                                # {"node_id": "1e2903b81bfa81bd624fb19cb12a74288b9c99ab3a49439eb8bbff4605e02d3f", "module": "proposalBuilder", "epoch": 7, "beacon": "0xea2f1811", "atx": "f378513b25", "weight": 259112, "ref": "6c6b3d00fc", "prev": 28243, "slots": 6, "eligible": 6, "eligible by layer": [{"layer": 28243, "slots": 1}, {"layer": 29112, "slots": 1}, {"layer": 29534, "slots": 1}, {"layer": 31068, "slots": 1}, {"layer": 31168, "slots": 1}, {"layer": 31578, "slots": 1}], "name": "proposalBuilder"}

                                json_object = json.loads(json_data)
                                # 从"layers to num proposals"中提取层的列表
                                eligible_layers = [
                                    entry["layer"] for entry in json_object["eligible by layer"]
                                ]
                                config = configparser.ConfigParser()
                                config.add_section(收款地址)
                                rewards = f"Eligible for rewards in layers {', '.join(map(str, eligible_layers))}"
                                epoch = json_object["epoch"]
                                集_奖励块状态 = '【已出现' + str(epoch) + '纪元奖励块】'
                                config.set(收款地址, 'block', rewards)
                                try:
                                    with open(os.path.join(app_directory, "奖励块.ini"), "w") as file:
                                        config.write(file)
                                        集_奖励块状态 = '【已保存' + str(epoch) + '纪元奖励块】'
                                except Exception:
                                    pass
                            else:
                                pass
                            集_p2pnum = count_unique_ips(集_pid)
                            setTilet()
                        except json.JSONDecodeError:
                            pass
            elif 'generating proof with PoW flags' in line:
                集_当前状态 = '【正在计算并扫盘】'
                setTilet()
                timestr = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
                os.path.dirname(os.path.realpath(sys.argv[0]))
                app_directory = os.path.dirname(os.path.realpath(sys.argv[0]))
                with open(os.path.join(app_directory, "calctime.txt"), "a") as time_file:
                    time_file.write(P盘文件路径.replace('\\', '\\\\') + ' ' + timestr + '\n')
            elif 'Finished reading POST data' in line:
                集_当前状态 = '【扫盘完毕】'
                setTilet()
                timestr = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
                os.path.dirname(os.path.realpath(sys.argv[0]))
                app_directory = os.path.dirname(os.path.realpath(sys.argv[0]))
                with open(os.path.join(app_directory, "FoundProof.txt"), "a") as time_file:
                    time_file.write(P盘文件路径.replace('\\', '\\\\') + ' ' + timestr + '\n')


def cmd_exec(command: str, ensure_success: bool = True) -> int:
    global 集_pid
    cmd = shlex.split(command)

    process = subprocess.Popen(
        cmd,
        shell=True,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )
    _logger.debug("等待go-spacemesh启动")
    psu_proc = psutil.Process(process.pid)
    pcs = None
    # 这里不能立即得到sub_proc的子程序，我这里作延时处理
    for i in range(4):
        time.sleep(1)
        _logger.debug(f'尝试检测子进程-{i + 1}')
        # 获取所有子程序
        pcs = psu_proc.children(recursive=True)
        if len(pcs):
            break
    if len(pcs):
        _logger.debug(f'检测到子进程{len(pcs)}个')
    else:
        _logger.warning(f'未检测到子进程,启动失败')
        os.system('pause')
        sys.exit()
        return
    proc = pcs[0]
    集_pid = proc.pid
    _logger.debug(f"started command with PID={集_pid}")
    def log_warp(func):
        def _wrapper(line: str):
            return func("\t" + line.strip())

        return _wrapper

    read_stdout = TextReadLineThread(process.stdout.readline, log_warp(_logger.info))
    read_stderr = TextReadLineThread(process.stderr.readline, log_warp(_logger.warning))
    read_stdout.start()
    read_stderr.start()

    try:
        read_stdout.join()
        _logger.debug("stdout reading finish")
        read_stderr.join()
        _logger.debug("stderr reading finish")
        ret = process.wait()
        _logger.debug("process finish")
    except:
        _logger.warning("命令已停止")
        return 0

    _logger.info("executed command with exit-code={}".format(ret))
    if ensure_success and ret != 0:
        raise CommandExecutionException(command=command, exit_code=ret)
    return ret



if __name__ == '__main__':
    app_directory = os.path.dirname(os.path.realpath(sys.argv[0]))
    config_path = os.path.join(app_directory, 'work.ini')
    config_data = read_ini_config(config_path)

    端口 = ''
    区块存放文件夹名称 = ''
    nonces = ''
    threads = ''
    go目录 = ''
    CPU挂机 = ''
    if config_data:
        _logger.debug("配置信息：")
        端口 = config_data['端口']
        P盘文件路径 = config_data['P盘文件路径']
        区块存放文件夹名称 = config_data['区块存放文件夹名称']
        收款地址 = config_data['收款地址']
        nonces = config_data['nonces']
        threads = config_data['threads']
        go目录 = config_data['go目录']
        CPU挂机 = config_data['CPU挂机']
        for key, value in config_data.items():
            _logger.debug(f"{key}: {value}")
    else:
        _logger.warning("未找到挖矿配置信息,软件退出")
        os.system('pause')
        sys.exit()
    setTilet()
    if check_file_exists(os.path.join(P盘文件路径, 'key.bin')) == False:
        _logger.debug("key.bin 文件不存在,软件退出")
        os.system('pause')
        sys.exit()
    if check_file_exists(os.path.join(P盘文件路径, 'postdata_metadata.json')) == False:
        _logger.debug("key.bin 文件不存在,软件退出")
        os.system('pause')
        sys.exit()

    if check_file_exists(os.path.join(go目录, 'go-spacemesh.exe')) == False or check_file_exists(
            os.path.join(go目录, 'profiler.exe')) == False or check_file_exists(
            os.path.join(go目录, 'post.dll')) == False:
        _logger.debug("go-spacemesh官方文件不存在,软件退出")
        os.system('pause')
        sys.exit()

    metadata_path = os.path.join(P盘文件路径, 'postdata_metadata.json')
    NodeId = ''
    NumUnits = ''
    MaxFileSize = ''
    if os.path.exists(metadata_path):
        metadata = read_postdata_metadata(metadata_path)
        if metadata:
            NodeId = metadata.get('NodeId', '')
            NumUnits = metadata.get('NumUnits', 0)
            MaxFileSize = metadata.get('MaxFileSize', 0)

            _logger.info(f"NodeId: {NodeId}")
            _logger.info(f"NumUnits: {NumUnits}")
            _logger.info(f"MaxFileSize: {MaxFileSize}")
        else:
            _logger.debug("无法解析 postdata_metadata.json 文件的内容,软件退出")
            os.system('pause')
            sys.exit()
    else:
        _logger.error("postdata_metadata.json 文件不存在,软件退出")
        os.system('pause')
        sys.exit()

    当前端口 = int(端口)
    端口开放 = False
    for _ in range(100):
        if is_port_open(当前端口):
            listen = str(当前端口)
            端口 = 当前端口
            当前端口 = 当前端口 + 1
            端口开放 = True
            break
        else:
            当前端口 = 当前端口 + 1
    if 端口开放 == False:
        _logger.debug("端口检测失败, 软件关闭")
        os.system('pause')
        sys.exit()

    端口开放 = False
    for _ in range(100):
        if is_port_open(当前端口):
            public_listener = str(当前端口)
            当前端口 = 当前端口 + 1
            端口开放 = True
            break
        else:
            当前端口 = 当前端口 + 1
    if 端口开放 == False:
        _logger.debug("端口检测失败, 软件关闭")
        os.system('pause')
        sys.exit()

    端口开放 = False
    for _ in range(100):
        if is_port_open(当前端口):
            private_listener = str(当前端口)
            当前端口 = 当前端口 + 1
            端口开放 = True
            break
        else:
            当前端口 = 当前端口 + 1
    if 端口开放 == False:
        _logger.debug("端口检测失败, 软件关闭")
        os.system('pause')
        sys.exit()

    端口开放 = False
    for _ in range(100):
        if is_port_open(当前端口):
            json_listener = str(当前端口)
            当前端口 = 当前端口 + 1
            端口开放 = True
            break
        else:
            当前端口 = 当前端口 + 1
    if 端口开放 == False:
        _logger.debug("端口检测失败, 软件关闭")
        os.system('pause')
        sys.exit()

    node_data = ''
    try:
        with open('config.txt', 'r') as file:
            node_data = json.load(file)
        node_data.setdefault("api", {})['grpc-public-listener'] = '0.0.0.0:' + public_listener
        node_data.setdefault("api", {})['grpc-private-listener'] = '127.0.0.1:' + private_listener
        node_data.setdefault("api", {})['grpc-json-listener'] = '0.0.0.0:' + json_listener
        node_data.setdefault("smeshing", {}).setdefault("smeshing-opts", {})['smeshing-opts-datadir'] = P盘文件路径
        node_data.setdefault("smeshing", {}).setdefault("smeshing-opts", {})["smeshing-opts-maxfilesize"] = int(
            MaxFileSize)
        node_data.setdefault("smeshing", {}).setdefault("smeshing-opts", {})["smeshing-opts-numunits"] = int(NumUnits)
        node_data.setdefault("smeshing", {}).setdefault("smeshing-opts", {})["smeshing-opts-throttle"] = False
        node_data.setdefault("smeshing", {}).setdefault("smeshing-opts", {})[
            "smeshing-opts-compute-batch-size"] = 1048576

        node_data.setdefault("smeshing", {})["smeshing-coinbase"] = 收款地址
        node_data.setdefault("smeshing", {})["smeshing-start"] = True

        node_data.setdefault("smeshing", {}).setdefault("smeshing-proving-opts", {})[
            "smeshing-opts-proving-nonces"] = int(nonces)
        node_data.setdefault("smeshing", {}).setdefault("smeshing-proving-opts", {})[
            "smeshing-opts-proving-threads"] = int(threads)
        if CPU挂机 == '1':
            node_data.setdefault("smeshing", {}).setdefault("smeshing-opts", {})["smeshing-opts-provider"] = 4294967295
        else:
            node_data.setdefault("smeshing", {}).setdefault("smeshing-opts", {})["smeshing-opts-provider"] = 0
        with open(os.path.join(app_directory, "node-config.json"), "w") as json_file:
            json.dump(node_data, json_file)
    except Exception as e:
        _logger.warning(f"An error occurred: {e},写出node-config.json配置异常,软件关闭")
        os.system('pause')
        sys.exit()

    cmd = go目录.replace('\\',
                         '\\\\') + '\\\\go-spacemesh.exe' + ' --listen /ip4/0.0.0.0/tcp/' + listen + ' --grpc-public-listener 0.0.0.0:' + public_listener + ' --grpc-private-listener 127.0.0.1:' + private_listener + ' --grpc-json-listener 0.0.0.0:' + json_listener + ' --config node-config.json --smeshing-opts-numunits ' + str(
        NumUnits) + ' -d ' + app_directory.replace('\\',
                                                   '\\\\') + '\\\\' + 区块存放文件夹名称 + ' --smeshing-coinbase ' + 收款地址 + ' --smeshing-start --smeshing-opts-datadir ' + P盘文件路径.replace(
        '\\', '\\\\') + ' --filelock lock.lock'
    try:
        cmd_exec(cmd, ensure_success=False)
    except Exception as e:
        pass
    _logger.debug("命令执行结束")
    sys.exit()
