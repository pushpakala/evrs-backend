# set up  db in __init__.py under my projects folder

from project import db, login_manager,admin,login
from werkzeug.security import generate_password_hash, check_password_hash
from flask_login import UserMixin,current_user,login_user,logout_user
from flask_admin.contrib.sqla import ModelView
# from flask_admin import AdminIndexView


        
@login_manager.user_loader
def load_user(user_id):
    return User.query.get(user_id)




class Admin_Headquaters(db.Model, UserMixin):
    admin_email = db.Column(db.String(64), primary_key=True, unique=True, index=True)
    admin_Name= db.Column(db.String(100))
    publicID = db.Column(db.String(100))
    password = db.Column(db.String(128))


    def __init__(self, admin_email,admin_Name, password):
        self.admin_email = admin_email
        self.admin_Name=admin_Name
        self.password = password

    def json(self):
        return {'admin_email':self.admin_email,'admin_name':self.admin_Name,'password':self.password}

    def check_password(self,password):     
        return check_password_hash(self.password,password)


@login_manager.user_loader
def load_user(user_id):
    return User.query.get(user_id)


class District(db.Model,UserMixin):
    __tablename__ = "District"
    id = db.Column(db.Integer,primary_key=True)
    DistrictName = db.Column(db.String(100))

    def __init__(self,DistrictName):
        self.DistrictName = DistrictName
        #self.id = id

    def json(self):
        return {'DistrictName':self.DistrictName,'id':id}

class Subcounty(db.Model,UserMixin):
    __tablename__ = "Subcounty"
    id = db.Column(db.Integer,primary_key=True)
    SubCountyName = db.Column(db.String(100))
    DistrictID = db.Column(db.String(100))

    def __init__(self,SubCountyName,DistrictID):
        self.SubCountyName = SubCountyName
        self.DistrictID = DistrictID

    def json(self):
        return {'SubCountyName':self.SubCountyName,'DistrictID':self.DistrictID}

class Parish(db.Model,UserMixin):
    __tablename__ = "Parish"
    id = db.Column(db.Integer,primary_key=True)
    ParishName = db.Column(db.String(100))
    SubCountyID = db.Column(db.String(100))
    DistrictID = db.Column(db.String(100))

    def __init__(self,ParishName,SubCountyID,DistrictID):
        self.ParishName = ParishName
        self.SubCountyID = SubCountyID
        self.DistrictID = DistrictID

    def json(self):
        return {'ParishName':self.ParishName,'SubCountyID':self.SubCountyID,'DistrictID':self.DistrictID,'id':id}

class PollingStation(db.Model,UserMixin):
    __tablename__ = "Polling Station"
    id = db.Column(db.Integer,primary_key=True)
    Name = db.Column(db.String(100))
    ParishID = db.Column(db.String(100))
    SubCountyID = db.Column(db.String(100))
    DistrictID = db.Column(db.String(100))
    file=db.Column(db.String(100))

    def __init__(self,Name,ParishID,SubCountyID,DistrictID,file):
        self.Name = Name
        self.ParishID = ParishID
        self.SubCountyID = SubCountyID
        self.DistrictID = DistrictID
        self.file=file

    def json(self):
        return {'PollingStationName':self.Name,'ParishID':self.ParishID,'SubCountyID':self.SubCountyID,'DistrictID':self.DistrictID,'file':self.file}

class PollingCategory(db.Model,UserMixin):
    __tablename__ = "Polling Category"
    id = db.Column(db.Integer,primary_key=True)
    Category = db.Column(db.String(100))

    def __init__(self,Category):
        self.Category = Category

    def json(self):
        return {'Category':self.Category,'id':id}

class Candidate(db.Model,UserMixin):
    __tablename__ = "Candidate"
    id = db.Column(db.Integer,primary_key=True)
    Name = db.Column(db.String(100))
    Photo = db.Column(db.String(100))
    Category = db.Column(db.String(100))
    LocationID = db.Column(db.String(100))

    def __init__(self,Name,Photo,Category,LocationID):
        self.Name = Name
        self.Photo = Photo
        self.Category = Category
        self.LocationID = LocationID

    def json(self):
        return {'Name':self.Name,'Photo':self.Photo,'Category':self.Category,'LocationID':self.LocationID}

class PollingData(db.Model,UserMixin):
    id = db.Column(db.Integer,primary_key=True)
    CandidateID = db.Column(db.String(100))
    CategoryID = db.Column(db.String(100))
    PollingStationID = db.Column(db.String(100))
    PollingResults = db.Column(db.String(100))

    def __init__(self,CandidateID,CategoryID,PollingStationID,PollingResults):
        self.CandidateID = CandidateID
        self.CategoryID = CategoryID
        self.PollingStationID = PollingStationID
        self.PollingResults = PollingResults

    def json(self):
        return {'CandidateID':self.CandidateID,'CategoryID':self.CategoryID,'PollingStationID':self.PollingStationID,'PollingResults':self.PollingResults}

class Results (db.Model,UserMixin):
    id = db.Column(db.Integer,primary_key=True)
    DISTRICT_CODE= db.Column(db.String(100))
    DISTRICT_NAME = db.Column(db.String(100))
    EA_CODE= db.Column(db.Integer)
    EA_NAME = db.Column(db.String(100))
    SCOUNTY_CODE = db.Column(db.Integer)
    SCOUNTY_NAME = db.Column(db.String(100))
    PARISH_CODE = db.Column(db.Integer)
    PARISH_NAME = db.Column(db.String(100))
    PS_CODE = db.Column(db.Integer)
    PS_NAME=db.Column(db.String(100))
    KT = db.Column(db.Integer)
    cand1 = db.Column(db.Integer)
    cand2 = db.Column(db.Integer)
    cand3 = db.Column(db.Integer)
    cand4 = db.Column(db.Integer)
    cand5 = db.Column(db.Integer)
    cand6 = db.Column(db.Integer)
    cand7 = db.Column(db.Integer)
    cand8 = db.Column(db.Integer)
    VALID_VOTE = db.Column(db.Integer)
    SPOILT_BALLOT = db.Column(db.Integer)
    INVALID_VOTE = db.Column(db.Integer)
    TOTAL_VOTE = db.Column(db.Integer)
                         
                        

    def __init__(self,DISTRICT_CODE,DISTRICT_NAME,EA_CODE,EA_NAME,SCOUNTY_CODE,SCOUNTY_NAME
                 ,PARISH_CODE,PARISH_NAME,PS_CODE,PS_NAME,KT,cand1,cand2,cand3,cand4,cand5,cand6,cand7,cand8,VALID_VOTE,SPOILT_BALLOT,INVALID_VOTE,TOTAL_VOTE):
        self.DISTRICT_CODE= DISTRICT_CODE
        self.DISTRICT_NAME= DISTRICT_NAME
        self.EA_CODE= EA_CODE
        self.EA_NAME = EA_NAME
        self.SCOUNTY_CODE = SCOUNTY_CODE
        self.SCOUNTY_NAME = SCOUNTY_NAME
        self.PARISH_CODE = PARISH_CODE
        self.PARISH_NAME = PARISH_NAME
        self.PS_CODE = PS_CODE
        self.PS_NAME=PS_NAME
        self.KT = KT
        self.cand1 = cand1
        self.cand2 = cand2
        self.cand3 = cand3
        self.cand4 = cand4
        self.cand5 = cand5
        self.cand6 = cand6
        self.cand7 = cand7
        self.cand8 = cand8
        self.VALID_VOTE = VALID_VOTE
        self.SPOILT_BALLOT = SPOILT_BALLOT
        self.INVALID_VOTE = INVALID_VOTE
        self.TOTAL_VOTE = TOTAL_VOTE
        
        

    def json(self):
        return {'DISTRICT_CODE': self.DISTRICT_CODE,'DISTRICT_NAME':self.DISTRICT_NAME,'EA_CODE':self.EA_CODE,'EA_NAME':self.EA_NAME,"SCOUNTY_CODE":self.SCOUNTY_CODE
                ,"SCOUNTY_NAME":self.SCOUNTY_NAME,"PARISH_CODE":self.PARISH_CODE,"PARISH_NAME":self.PARISH_NAME,"PS_CODE":self.PS_CODE,"PS_NAME":self.PS_NAME,"KT":self.KT,"cand1":self.cand1,"cand2":self.cand2,"cand3":self.cand3,
                "cand4":self.cand4,"cand5":self.cand5,"cand6":self.cand6,"cand7":self.cand7,"cand8":self.cand8,"VALID_VOTE":self.VALID_VOTE,"SPOILT_BALLOT":self.SPOILT_BALLOT,"INVALID_VOTE":self.INVALID_VOTE,
                "TOTAL_VOTE":self.TOTAL_VOTE}

class PresidentialTable(db.Model,UserMixin):
    id = db.Column(db.Integer,primary_key=True)
    Key=db.Column(db.String(100))
    DISTRICT_NAME = db.Column(db.String(100))
    candate1 = db.Column(db.Integer)
    candate2 = db.Column(db.Integer)
    candate3 = db.Column(db.Integer)
    candate4 = db.Column(db.Integer)
    candate5 = db.Column(db.Integer)
    candate6 = db.Column(db.Integer)
    candate7 = db.Column(db.Integer)
    candate8 = db.Column(db.Integer)
    winner=db.Column(db.String(100))
    margin=db.Column(db.Integer)

    def __init__(self,Key,DISTRICT_NAME,candate1,candate2,candate3,candate4,candate5,candate6,candate7,candate8,winner,margin):
        self.Key=Key
        self.DISTRICT_NAME= DISTRICT_NAME
        self.candate1 = candate1
        self.candate2 = candate2
        self.candate3 = candate3
        self.candate4 = candate4
        self.candate5 = candate5
        self.candate6 = candate6
        self.candate7 = candate7
        self.candate8 = candate8
        self.winner = winner
        self.margin = margin

    def json(self):
        return {'name':self.DISTRICT_NAME,'hc-key':self.Key,"cand1":self.candate1,"cand2":self.candate2,"cand3":self.candate3,
                "cand4":self.candate4,"cand5":self.candate5,"cand6":self.candate6,"cand7":self.candate7,"cand8":self.candate8,"winner":self.winner,"value":self.margin}

       

class Controller(ModelView):
    def is_accessible(self):
        return current_user.is_authenticated

    def not_auth(self):
        return "you are not authorised"
                      
admin.add_view(Controller(Results,db.session))
admin.add_view(Controller(PresidentialTable,db.session))   



db.create_all()
