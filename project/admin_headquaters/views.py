from project import app, db
from flask_restful import Resource, Api
from flask import flash, redirect, render_template, request, url_for,make_response
from flask_login import login_user,login_required, logout_user
from project.models import District,Subcounty,Parish,PollingStation,PollingCategory,Candidate,PollingData,Results,PresidentialTable,Admin_Headquaters
from project import db, login_manager,mail
from werkzeug.utils import secure_filename
from werkzeug.security import generate_password_hash,check_password_hash
import os
import functools
from flask_login import login_user,login_required,logout_user
import json
import logging
from flask import jsonify
import uuid
from werkzeug.security import generate_password_hash,check_password_hash
import jwt
from functools import wraps
from flask import send_file, send_from_directory, safe_join, abort
import datetime
from flask_mail import Message
import random
import datetime
import collections
import gspread
import itertools as it
import functools
import pandas as pd
from oauth2client.service_account import ServiceAccountCredentials
import operator
from sqlalchemy.sql import func
import glob, os
from base64 import b64encode

api = Api(app)

def token_required(f):
    @wraps(f)
    def decorated(*args,**kwargs):
        token = None
        try:
            
            if request.headers['X-Access_Token'] is not None:
                token = request.headers['X-Access_Token']
            if not token:
                return make_response('Invalid Token',401,{'www-Authenticate':'Invalid Token"'})
            try:
                data = jwt.decode(token,app.config['SECRET_KEY'])
                current_user = Admin_Headquaters.query.filter_by(admin_email=data['admin_email']).first()
            except:
                return make_response('Invalid Token',401,{'www-Authenticate':'Invalid Token"'})
            return f(current_user,*args,**kwargs)   

        except:
            return make_response('Invalid Token',401,{'www-Authenticate':'Invalid Token"'})

    return decorated


class Register2(Resource):
    
    #@staticmethod
    def post(self):
       
        data = request.get_json()
        
        admin_Name= data['Name']
        admin_email = data['email']
        #publicID = str(uuid.uuid4)
        password = data['password']
        confirm_password = data['confirm_password']
        if admin_email is None or password is None :
            return {'error':'error'}
        if password==confirm_password:
            user = Admin_Headquaters(admin_Name=admin_Name,admin_email=admin_email,password=password)
            db.session.add(user)
            db.session.commit()
            return data
        else:
            return {'error':'Could not creat account'}

##application login function
class LoginHeadquaters(Resource):
    def post(self):
        #data = request.authorization
        data = request.get_json()
        if not data or not data['username'] or not data['password']:
            return make_response('Could not verify1',401,{'www-Authenticate':'Basic realm-"login required!"'})        
        admin = Admin_Headquaters.query.filter_by(admin_email=data['username']).first()
        if not admin:
            return make_response('Could not verify2',401,{'www-Authenticate':'Basic realm-"login required!"'})       
        if admin.password == data['password']:
            token = jwt.encode({'admin_email':admin.admin_email,'exp':datetime.datetime.utcnow()+datetime.timedelta(minutes=120)},app.config['SECRET_KEY'])
            return jsonify({'token':token.decode('UTF-8'),'username':admin.admin_email,'admin_Name':admin.admin_Name})
        return make_response('Could not verify3',401,{'www-Authenticate':'Basic realm-"login required!"'})


                        
##pulls data from the excel document to the results table
##calculates totals for all candidates and puts them to presidential table together with hc-keys from geo json map file
class GetSheetDtata(Resource):
    def get(self):
        p=[]
        q=[]
        delete_q = Results.__table__.delete()
        db.session.execute(delete_q)
        db.session.commit()
        delete_k = PresidentialTable.__table__.delete()
        db.session.execute(delete_k)
        db.session.commit()
        scope = ['https://spreadsheets.google.com/feeds','https://www.googleapis.com/auth/drive']
        credentials = ServiceAccountCredentials.from_json_keyfile_name('ece-backend-0ee8e133bf5b.json', scope)
        gc = gspread.authorize(credentials)
        sheet = gc.open("UGANDAN-ELECTION").sheet1
        
        for x in sheet.get_all_records():
            p.append(x)
        
##        p.append(sheet.get_all_records())
        
        for element in p:
            DISTRICT_CODE=element['DISTRICT_CODE']
            DISTRICT_NAME=element['DISTRICT_NAME']
            EA_CODE=element['EA_CODE']
            EA_NAME=element['EA_NAME']
            SCOUNTY_CODE=element['SCOUNTY_CODE']
            SCOUNTY_NAME=element['SCOUNTY_NAME']
            PARISH_CODE=element['PARISH_CODE']
            PARISH_NAME=element['PARISH_NAME']
            PS_CODE=element['PS_CODE']
            PS_NAME=element['PS_NAME']
            KT=element['KT']
            cand1=element['ABED']
            cand2=element['AMAMA']
            cand3=element['BARYA']
            cand4=element['BENON']
            cand5=element['KIZZA']
            cand6=element['JOSEPH']
            cand7=element['MAUREEN']
            cand8=element['YOWERI']
            VALID_VOTE=element['VALID_VOTE']
            SPOILT_BALLOT=element['SPOILT_BALLOT']
            INVALID_VOTE=element['INVALID_VOTE']
            TOTAL_VOTE=element['TOTAL_VOTE']
            

            posttable=Results(DISTRICT_CODE=DISTRICT_CODE,DISTRICT_NAME=DISTRICT_NAME,EA_CODE=EA_CODE,EA_NAME=EA_NAME,
                              SCOUNTY_CODE=SCOUNTY_CODE,SCOUNTY_NAME=SCOUNTY_NAME,PARISH_CODE=PARISH_CODE,PARISH_NAME=PARISH_NAME,
                              PS_CODE=PS_CODE,PS_NAME=PS_NAME,KT=KT,cand1=cand1,cand2=cand2,cand8=cand8,
                              cand3=cand3,cand4=cand4,cand5=cand5,cand6=cand6,cand7=cand7,VALID_VOTE=VALID_VOTE,SPOILT_BALLOT=SPOILT_BALLOT,INVALID_VOTE=INVALID_VOTE,
                              TOTAL_VOTE=TOTAL_VOTE)
            db.session.add(posttable)
            db.session.commit()

        get_data=Results.query.all()
        winner=''
        margin=''
        list_=[]
        p=[x.json() for x in get_data]
        with open ("ug-all.geo.json") as file:
            data=file.read()
        data=json.loads(data)
        code_dict=dict()
        for x in data['features']:
            properties = x["properties"]
            code_dict[properties["hc-key"]] = properties["name"]
        code_dict["ug-2776"] = "Bukwo"
        code_dict["ug-2774"] = "Kibaale"
        code_dict["ug-1689"] = "Ssembabule"
        code_dict["ug-3388"] = "Kiruhura"

        code_dict_reverse=dict([(key.upper(), value) for value, key in code_dict.items()])
        counter = collections.Counter()
        counter1 = collections.Counter()
        counter2 = collections.Counter()
        counter3 = collections.Counter()
        counter4 = collections.Counter()
        counter5 = collections.Counter()
        counter6 = collections.Counter()
        counter7 = collections.Counter()
        for d in p:
            counter[d['DISTRICT_NAME']] += d['cand1']
            counter1[d['DISTRICT_NAME']] += d['cand2']
            counter2[d['DISTRICT_NAME']] += d['cand3']
            counter3[d['DISTRICT_NAME']] += d['cand4']
            counter4[d['DISTRICT_NAME']] += d['cand5']
            counter5[d['DISTRICT_NAME']] += d['cand6']
            counter6[d['DISTRICT_NAME']] += d['cand7']
            counter7[d['DISTRICT_NAME']] += d['cand8']
##            for elm in [counter,counter1,counter2,counter3,counter4,counter5,counter6,counter7]:
##                list_.append(elm)
##            
##            list_.append([counter,counter1,counter2,counter3,counter4,counter5,counter6,counter7])
        pre=PresidentialTable.query.all()
        can1=[{'DISTRICT_NAME': name, 'cand1': cand1} for name, cand1 in counter.items()]
        can2=[{'DISTRICT_NAME': name, 'cand2': cand2} for name, cand2 in counter1.items()]
        can3=[{'DISTRICT_NAME': name, 'cand3': cand3} for name, cand3 in counter2.items()]
        can4=[{'DISTRICT_NAME': name, 'cand4': cand4} for name, cand4 in counter3.items()]
        can5=[{'DISTRICT_NAME': name, 'cand5': cand5} for name, cand5 in counter4.items()]
        can6=[{'DISTRICT_NAME': name, 'cand6': cand6} for name, cand6 in counter5.items()]
        can7=[{'DISTRICT_NAME': name, 'cand7': cand7} for name, cand7 in counter6.items()]
        can8=[{'DISTRICT_NAME': name, 'cand8': cand8} for name, cand8 in counter7.items()]
        
        hc_key=code_dict_reverse
        hc=[{'DISTRICT_NAME': name, 'Key': keyn} for name, keyn in hc_key.items()]
        
        sums=[*can1,*can2,*can3,*can4,*can5,*can6,*can7,*can8,*hc]
        d = collections.defaultdict(dict)
        data=[]
        for l in sums:
            d[l['DISTRICT_NAME']].update(l)
            
        for k,v in d.items():
            data.append(v)
        g=[]
        for h in data:
            seq = [{k:v} for k,v in h.items() if not isinstance(v, str)]
            sew=dict(collections.ChainMap(*seq))
            keyMax = max(sew.items(), key = operator.itemgetter(1))
            win={keyMax[0]:keyMax[1]}
            b=tuple(win.items())[0][0] 
            a=tuple(win.items())[0][1]
            if b=='cand1':
                margin=-10
            elif b=='cand2':
                margin=-20
            elif b=='cand3':
                margin=-30
            elif b=='cand4':
                margin=-40
            elif b=='cand5':
                margin=-50
            elif b=='cand6':
                margin=-60
            elif b=='cand7':
                margin=-70
            elif b=='cand8':
                margin=-80
            Key=h['Key']
            DISTRICT_NAME=h['DISTRICT_NAME']
            cand1=h['cand1']
            cand2=h['cand2']
            cand3=h['cand3']
            cand4=h['cand4']
            cand5=h['cand5']
            cand6=h['cand6']
            cand7=h['cand7']
            cand8=h['cand8']
            winner=b
            
            
            update=PresidentialTable(Key=Key,DISTRICT_NAME=DISTRICT_NAME,candate1=cand1,candate2=cand2,candate3=cand3,
                                     candate4=cand4,candate5=cand5,candate6=cand6,candate7=cand7,candate8=cand8,winner=winner,margin=margin)
            db.session.add(update)
            db.session.commit()
            
##resource to manipulate data from the geo json mapfile to align hc-keys to respective districts          
class MapData(Resource):
    def get(self):
        get_data=Results.query.all()
        winner=''
        margin=''
        list_=[]
        p=[x.json() for x in get_data]
        with open ("ug-all.geo.json") as file:
            data=file.read()
        data=json.loads(data)
        code_dict=dict()
        for x in data['features']:
            properties = x["properties"]
            code_dict[properties["hc-key"]] = properties["name"]
        code_dict["ug-2776"] = "Bukwo"
        code_dict["ug-2774"] = "Kibaale"
        code_dict["ug-1689"] = "Ssembabule"
        code_dict["ug-3388"] = "Kiruhura"

        code_dict_reverse=dict([(key.upper(), value) for value, key in code_dict.items()])
        counter = collections.Counter()
        counter1 = collections.Counter()
        counter2 = collections.Counter()
        counter3 = collections.Counter()
        counter4 = collections.Counter()
        counter5 = collections.Counter()
        counter6 = collections.Counter()
        counter7 = collections.Counter()
        for d in p:
            counter[d['DISTRICT_NAME']] += d['cand1']
            counter1[d['DISTRICT_NAME']] += d['cand2']
            counter2[d['DISTRICT_NAME']] += d['cand3']
            counter3[d['DISTRICT_NAME']] += d['cand4']
            counter4[d['DISTRICT_NAME']] += d['cand5']
            counter5[d['DISTRICT_NAME']] += d['cand6']
            counter6[d['DISTRICT_NAME']] += d['cand7']
            counter7[d['DISTRICT_NAME']] += d['cand8']
##            for elm in [counter,counter1,counter2,counter3,counter4,counter5,counter6,counter7]:
##                list_.append(elm)
##            
##            list_.append([counter,counter1,counter2,counter3,counter4,counter5,counter6,counter7])
        pre=PresidentialTable.query.all()
        can1=[{'DISTRICT_NAME': name, 'cand1': cand1} for name, cand1 in counter.items()]
        can2=[{'DISTRICT_NAME': name, 'cand2': cand2} for name, cand2 in counter1.items()]
        can3=[{'DISTRICT_NAME': name, 'cand3': cand3} for name, cand3 in counter2.items()]
        can4=[{'DISTRICT_NAME': name, 'cand4': cand4} for name, cand4 in counter3.items()]
        can5=[{'DISTRICT_NAME': name, 'cand5': cand5} for name, cand5 in counter4.items()]
        can6=[{'DISTRICT_NAME': name, 'cand6': cand6} for name, cand6 in counter5.items()]
        can7=[{'DISTRICT_NAME': name, 'cand7': cand7} for name, cand7 in counter6.items()]
        can8=[{'DISTRICT_NAME': name, 'cand8': cand8} for name, cand8 in counter7.items()]
        
        hc_key=code_dict_reverse
        hc=[{'DISTRICT_NAME': name, 'Key': keyn} for name, keyn in hc_key.items()]
        
        sums=[*can1,*can2,*can3,*can4,*can5,*can6,*can7,*can8,*hc]
        d = collections.defaultdict(dict)
        data=[]
        for l in sums:
            d[l['DISTRICT_NAME']].update(l)
            
        for k,v in d.items():
            data.append(v)
        g=[]
        for h in data:
            seq = [{k:v} for k,v in h.items() if not isinstance(v, str)]
            sew=dict(collections.ChainMap(*seq))
            keyMax = max(sew.items(), key = operator.itemgetter(1))
            win={keyMax[0]:keyMax[1]}
            b=tuple(win.items())[0][0] 
            a=tuple(win.items())[0][1]
            if b=='cand1':
                margin=-10
            elif b=='cand2':
                margin=-20
            elif b=='cand3':
                margin=-30
            elif b=='cand4':
                margin=-40
            elif b=='cand5':
                margin=-50
            elif b=='cand6':
                margin=-60
            elif b=='cand7':
                margin=-70
            elif b=='cand8':
                margin=-80
            Key=h['Key']
            DISTRICT_NAME=h['DISTRICT_NAME']
            cand1=h['cand1']
            cand2=h['cand2']
            cand3=h['cand3']
            cand4=h['cand4']
            cand5=h['cand5']
            cand6=h['cand6']
            cand7=h['cand7']
            cand8=h['cand8']
            winner=b
            
            
            update=PresidentialTable(Key=Key,DISTRICT_NAME=DISTRICT_NAME,candate1=cand1,candate2=cand2,candate3=cand3,
                                     candate4=cand4,candate5=cand5,candate6=cand6,candate7=cand7,candate8=cand8,winner=winner,margin=margin)
            db.session.add(update)
            db.session.commit()
        
                
##map data in exact high chart format           
class SendMapData(Resource):
    @token_required
    def get(self,current_user):
        get_data=PresidentialTable.query.all()
        code_data=[x.json() for x in get_data]
        with open ("ug-all.geo.json") as file:
            data=file.read()
        data=json.loads(data)
        code_dict=dict()
        sata=[]
        for x in data['features']:
            properties = x["properties"]
            geometry=x["geometry"]
            for y in code_data:
                if properties['hc-key']==y['hc-key']:
                    y['properties']=properties
                    y['geometry']=geometry
                    sata.append(y)
        return sata
                
                    
##calculates totals of candidates overall                   
class GetPresidentailCandidates(Resource):
    @token_required
    def get(self,current_user):
        data= request.get_json()
        president= PresidentialTable.query.all()
        qry = db.session.query( 
                    func.sum(PresidentialTable.candate1).label("cand1"),
                     func.sum(PresidentialTable.candate2).label("cand2"),
                    func.sum(PresidentialTable.candate3).label("cand3"),
                    func.sum(PresidentialTable.candate4).label("cand4"),
                    func.sum(PresidentialTable.candate5).label("cand5"),
                    func.sum(PresidentialTable.candate6).label("cand6"),
                    func.sum(PresidentialTable.candate7).label("cand7"),
                    func.sum(PresidentialTable.candate8).label("cand8")
                    
                    )
        
        for item in qry:
            
            return {"cand1":item[0],"cand2":item[1],"cand3":item[2],"cand4":item[3],"cand5":item[4],"cand6":item[5],"cand7":item[6],"cand8":item[7]}
        
##gets candidates results from district to subcounty to parish to polling station            
class Candidates(Resource):
    @token_required
    def post(self,current_user):
        data= request.get_json()
        if data['Category']=='Presidential' and data['District'] == '' and data['Subconty']=="" and data['PARISH_NAME']=="":
            president= PresidentialTable.query.all()
            qry = db.session.query( 
                        func.sum(PresidentialTable.candate1).label("cand1"),
                         func.sum(PresidentialTable.candate2).label("cand2"),
                        func.sum(PresidentialTable.candate3).label("cand3"),
                        func.sum(PresidentialTable.candate4).label("cand4"),
                        func.sum(PresidentialTable.candate5).label("cand5"),
                        func.sum(PresidentialTable.candate6).label("cand6"),
                        func.sum(PresidentialTable.candate7).label("cand7"),
                        func.sum(PresidentialTable.candate8).label("cand8")
                        
                        )
            
            for item in qry:
                
                return {"cand1":item[0],"cand2":item[1],"cand3":item[2],"cand4":item[3],"cand5":item[4],"cand6":item[5],"cand7":item[6],"cand8":item[7]}
        elif data['Category'].upper()=='PRESIDENTIAL' and PresidentialTable.query.filter_by(DISTRICT_NAME=data['District'].upper()) and data['Subconty']=="" and data['PARISH_NAME']=="":
            get_data=PresidentialTable.query.filter_by(DISTRICT_NAME=data['District'].upper()).first()
            return get_data.json()
        elif Results.query.filter_by(SCOUNTY_NAME=data['Subconty'].upper())and data['District'] and data['Category'] and data['PARISH_NAME']=='':
            get_sub=Results.query.filter_by(SCOUNTY_NAME=data['Subconty'].upper())
            sub=[x.json() for x in get_sub]
            counter = collections.Counter()
            counter1 = collections.Counter()
            counter2 = collections.Counter()
            counter3 = collections.Counter()
            counter4 = collections.Counter()
            counter5 = collections.Counter()
            counter6 = collections.Counter()
            counter7 = collections.Counter()
            for d in sub:
                counter[d['SCOUNTY_NAME']] += d['cand1']
                counter1[d['SCOUNTY_NAME']] += d['cand2']
                counter2[d['SCOUNTY_NAME']] += d['cand3']
                counter3[d['SCOUNTY_NAME']] += d['cand4']
                counter4[d['SCOUNTY_NAME']] += d['cand5']
                counter5[d['SCOUNTY_NAME']] += d['cand6']
                counter6[d['SCOUNTY_NAME']] += d['cand7']
                counter7[d['SCOUNTY_NAME']] += d['cand8']
            can1=[{'SCOUNTY_NAME': name, 'cand1': cand1} for name, cand1 in counter.items()]
            can2=[{'SCOUNTY_NAME': name, 'cand2': cand2} for name, cand2 in counter1.items()]
            can3=[{'SCOUNTY_NAME': name, 'cand3': cand3} for name, cand3 in counter2.items()]
            can4=[{'SCOUNTY_NAME': name, 'cand4': cand4} for name, cand4 in counter3.items()]
            can5=[{'SCOUNTY_NAME': name, 'cand5': cand5} for name, cand5 in counter4.items()]
            can6=[{'SCOUNTY_NAME': name, 'cand6': cand6} for name, cand6 in counter5.items()]
            can7=[{'SCOUNTY_NAME': name, 'cand7': cand7} for name, cand7 in counter6.items()]
            can8=[{'SCOUNTY_NAME': name, 'cand8': cand8} for name, cand8 in counter7.items()]
            sums=[*can1,*can2,*can3,*can4,*can5,*can6,*can7,*can8]
            d = collections.defaultdict(dict)
            data=[]
            for l in sums:
                d[l['SCOUNTY_NAME']].update(l)
                
            for k,v in d.items():
                return v
        elif Results.query.filter_by(SCOUNTY_NAME=data['Subconty'].upper())and data['District'] and data['Category'] and Results.query.filter_by(PARISH_NAME=data['PARISH_NAME'].upper()):
            get_pa=Results.query.filter_by(PARISH_NAME=data['PARISH_NAME'].upper())
            parish=[x.json() for x in get_pa]
            counter = collections.Counter()
            counter1 = collections.Counter()
            counter2 = collections.Counter()
            counter3 = collections.Counter()
            counter4 = collections.Counter()
            counter5 = collections.Counter()
            counter6 = collections.Counter()
            counter7 = collections.Counter()
            for d in parish:
                counter[d['PARISH_NAME']] += d['cand1']
                counter1[d['PARISH_NAME']] += d['cand2']
                counter2[d['PARISH_NAME']] += d['cand3']
                counter3[d['PARISH_NAME']] += d['cand4']
                counter4[d['PARISH_NAME']] += d['cand5']
                counter5[d['PARISH_NAME']] += d['cand6']
                counter6[d['PARISH_NAME']] += d['cand7']
                counter7[d['PARISH_NAME']] += d['cand8']
            can1=[{'PARISH_NAME': name, 'cand1': cand1} for name, cand1 in counter.items()]
            can2=[{'PARISH_NAME': name, 'cand2': cand2} for name, cand2 in counter1.items()]
            can3=[{'PARISH_NAME': name, 'cand3': cand3} for name, cand3 in counter2.items()]
            can4=[{'PARISH_NAME': name, 'cand4': cand4} for name, cand4 in counter3.items()]
            can5=[{'PARISH_NAME': name, 'cand5': cand5} for name, cand5 in counter4.items()]
            can6=[{'PARISH_NAME': name, 'cand6': cand6} for name, cand6 in counter5.items()]
            can7=[{'PARISH_NAME': name, 'cand7': cand7} for name, cand7 in counter6.items()]
            can8=[{'PARISH_NAME': name, 'cand8': cand8} for name, cand8 in counter7.items()]
            sums=[*can1,*can2,*can3,*can4,*can5,*can6,*can7,*can8]
            d = collections.defaultdict(dict)
            data=[]
            for l in sums:
                d[l['PARISH_NAME']].update(l)
                
            for k,v in d.items():
                return v
            
        else:
            return {"eror":"passed"}
        
##get subcounties in a district
class candidateDistrict(Resource):
    @token_required
    def post(self,current_user):
        data= request.get_json()
        d=data['District'].upper()
        if Results.query.filter_by(DISTRICT_NAME=d):
            get_data=Results.query.filter_by(DISTRICT_NAME=d)
            items=[x.json() for x in get_data]
            new=[]
            for val in items:
                k=val['SCOUNTY_NAME']
                new.append(k)
                
            new_=list(dict.fromkeys(new))
            drop=[{"text":s} for s in new_]
            return drop
        else:
            return {"eror":"passed"}
##get parishes in a subcounty
class candidateParish(Resource):
    @token_required
    def post(self,current_user):
        data= request.get_json()
        d=data['District'].upper()
        if Results.query.filter_by(DISTRICT_NAME=d)and Results.query.filter_by(SCOUNTY_NAME=data['Subconty'].upper()):
            get_data=Results.query.filter_by(DISTRICT_NAME=d,SCOUNTY_NAME=data['Subconty'].upper())
            items=[x.json() for x in get_data]
            new=[]
            for val in items:
                k=val['PARISH_NAME']
                new.append(k)
                
            new_=list(dict.fromkeys(new))
            drop=[{"text":s} for s in new_]
            return drop
        else:
            return {"eror":"passed"}

class get_districts(Resource):
    @token_required
    def get(self,current_user):
        data= request.get_json()
        get_district=Results.query.all()
        districts=[x.json()['DISTRICT_NAME'] for x in get_district]
        my_districts=sorted(list(dict.fromkeys(districts)))
        final_list=[{"text":s} for s in my_districts]
        return final_list
    
class get_candidates(Resource):
    @token_required
    def post(self,current_user):
        data= request.get_json()
        if Candidate.query.filter_by(Name=data['Name']).first():
            return {"msg":"candidate already exists"}
        else:
            pass
        Name = data['Name']
        Photo=''
        Category=data['Category']
        LocationID=''
        post_cand=Candidate(Name=Name,Photo=Photo,Category=Category,LocationID=LocationID)
        db.session.add(post_cand)
        db.session.commit()

class get_allcandidates(Resource):
    @token_required
    def post(self,current_user):
        data= request.get_json()
        if data['Category']=='Presidential':
            all_=Candidate.query.all()
            new_=[x.json() for x in all_]
            k=['cand1','cand2','cand3','cand4','cand5','cand6','cand7','cand8']
            g=[]
            c=0
            for x in new_:
               g.append(x['Name'])
            dictionary=dict(zip(k,g))
            return dictionary
        else:
            return{"msg":"category changed"}

class polling_file(Resource):
    @token_required
    def get(self,current_user):
        list_=[]
        for file in os.listdir(app.config['UPLOAD_FOLDER']):
            list_.append({"text":file})
        return list_
##get diclaration form
class single_file(Resource):
    
    def post(self):
        data= request.get_json()
        name = data["ps_name"]
        
        try:
            path_=os.path.join(app.config['UPLOAD_FOLDER'],name)
            with open(path_,"rb") as file:
                data=b64encode(file.read()).decode()
                return {"media":data}
            
           
        

        except FileNotFoundError:
            abort(404)
        
        


class candidateSubcounty(Resource):
    @token_required
    def post(self,current_user):
        data= request.get_json()
        d=data['District'].upper()
        if  Results.query.filter_by(DISTRICT_NAME=d)and Results.query.filter_by(SCOUNTY_NAME=data['Subconty'].upper()) and Results.query.filter_by(PARISH_NAME=data['PARISH_NAME'].upper()) :
            
            get_sub=Results.query.filter_by(DISTRICT_NAME=d,SCOUNTY_NAME=data['Subconty'].upper(),PARISH_NAME=data['PARISH_NAME'].upper())
            sub=[x.json() for x in get_sub]
            counter = collections.Counter()
            counter1 = collections.Counter()
            counter2 = collections.Counter()
            counter3 = collections.Counter()
            counter4 = collections.Counter()
            counter5 = collections.Counter()
            counter6 = collections.Counter()
            counter7 = collections.Counter()
            for d in sub:
                counter[d['PS_NAME']] += d['cand1']
                counter1[d['PS_NAME']] += d['cand2']
                counter2[d['PS_NAME']] += d['cand3']
                counter3[d['PS_NAME']] += d['cand4']
                counter4[d['PS_NAME']] += d['cand5']
                counter5[d['PS_NAME']] += d['cand6']
                counter6[d['PS_NAME']] += d['cand7']
                counter7[d['PS_NAME']] += d['cand8']
            can1=[{'PS_NAME': name, 'cand1': cand1} for name, cand1 in counter.items()]
            can2=[{'PS_NAME': name, 'cand2': cand2} for name, cand2 in counter1.items()]
            can3=[{'PS_NAME': name, 'cand3': cand3} for name, cand3 in counter2.items()]
            can4=[{'PS_NAME': name, 'cand4': cand4} for name, cand4 in counter3.items()]
            can5=[{'PS_NAME': name, 'cand5': cand5} for name, cand5 in counter4.items()]
            can6=[{'PS_NAME': name, 'cand6': cand6} for name, cand6 in counter5.items()]
            can7=[{'PS_NAME': name, 'cand7': cand7} for name, cand7 in counter6.items()]
            can8=[{'PS_NAME': name, 'cand8': cand8} for name, cand8 in counter7.items()]
            sums=[*can1,*can2,*can3,*can4,*can5,*can6,*can7,*can8]
            d = collections.defaultdict(dict)
            data=[]
            for l in sums:
                d[l['PS_NAME']].update(l)
                
            for k,v in d.items():
                data.append(v)
            return data
            
        
            
            
            
            
        
        
                                                       
      
 
