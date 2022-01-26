import sys,subprocess,time

r = subprocess.Popen(['lsof', '-n','-P'], stdout=subprocess.PIPE).communicate()[0]
r=str(r, encoding='utf-8')
r_list=r.split("\n")
r3=[]
A=[]
for i in range(len(r_list)):
    r2=r_list[i].split()
    r2=r2[:1]
    if r2:
        r3.append(r2[0])
A=list(set(r3))
for j in range(len(A)):
    print(A[j])
    time.sleep(0.3)
