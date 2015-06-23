names = file("teamnames").read().split("\n")

layout = []
count = 1
for i in names:
    if i[0] == "*":
        layout.append(i)
    else:
        layout.append(str(count))
        count = count + 1
layout = "|".join(layout)
teams = []
count = 1
for i in names:
    if i[0] != "*":
        teams.append("%s:172.26.%d.1" % (i, count))
    count = count + 1
teams = "\n".join(teams)
conf = "%s\n%s" % (layout, teams)
file("cddc.conf", 'w').write(conf)


