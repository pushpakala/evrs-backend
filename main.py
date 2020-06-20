from project import app, db
from flask_restful import Resource, Api
from flask_restful import Api


from project.admin_headquaters.views import LoginHeadquaters,single_file,polling_file,Register2,GetPresidentailCandidates,GetSheetDtata,MapData,SendMapData,Candidates,get_districts,candidateSubcounty,candidateDistrict,candidateParish,get_candidates,get_allcandidates

api = Api(app)
########
api.add_resource(LoginHeadquaters, '/LoginHeadquaters')
api.add_resource(Register2, '/Register2')
api.add_resource(GetPresidentailCandidates, '/GetPresidentailCandidates')
api.add_resource(GetSheetDtata, '/GetSheetDtata')
api.add_resource(MapData, '/MapData')
api.add_resource(SendMapData, '/SendMapData')
api.add_resource(Candidates, '/Candidates')
api.add_resource(candidateDistrict, '/candidateDistrict')
api.add_resource(candidateSubcounty, '/candidateSubcounty')
api.add_resource(candidateParish, '/candidateParish')
api.add_resource(get_districts, '/get_districts')
api.add_resource(get_candidates, '/get_candidates')
api.add_resource(get_allcandidates, '/get_allcandidates')
api.add_resource(polling_file, '/polling_file')
api.add_resource(single_file, '/single_file')






if __name__ == '__main__':
    app.run(debug=True)

