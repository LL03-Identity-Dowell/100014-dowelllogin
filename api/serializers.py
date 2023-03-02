from rest_framework import serializers
from loginapp.models import Account, CustomSession
#from voc_nps.models import Rating
class UserSerializer(serializers.ModelSerializer):
    class Meta:
        model=Account
        fields = ['id','username', 'email', 'phone','first_name','last_name','role','teamcode','password','phonecode','profile_image']
        # fields = ['username','password','email','role','teamcode']
        extra_kwargs={
            'password':{'write_only':True},
            'profile_image': {'required': False},
            'role': {'read_only': True},
            'id':{'read_only':True}
            }
    def create(self, validated_data):
        password=validated_data.pop('password',None)
        instance = self.Meta.model(**validated_data)
        if password is not None:
            instance.set_password(password)
        instance.save()
        return instance
class UserUpdateSerializer(serializers.ModelSerializer):
    class Meta:
        model=Account
        fields = ['id','username', 'email', 'phone','first_name','last_name','role','teamcode','phonecode','profile_image','datatype']
        extra_kwargs={
            'id':{'read_only':True},
            'profile_image': {'required': False},
            'username': {'required': False},
            'email': {'required': False},
            'phone': {'required': False},
            'first_name': {'required': False},
            'last_name': {'required': False},
            'team_code': {'required': False},
            'phonecode': {'required': False},
            'datatype': {'required': False},
            }


class CustomSessionSerializer(serializers.ModelSerializer):
    class Meta:
        model = CustomSession
        fields = "__all__"

# class RatingSerializer(serializers.ModelSerializer):
#     class Meta:
#         model=Rating
#         fields = ['orientation','rating','scolor','rcolor','fcolor','bcolor','time','format','template_name','text','name']

# class YourSerializer(serializers.Serializer):
#   """Your data serializer, define your fields here."""
#   comments = serializers.IntegerField()
#   likes = serializers.IntegerField()
# views.py

# from rest_framework import views
# from rest_framework.response import Response

# from .serializers import YourSerializer

# class YourView(views.APIView):

#     def get(self, request):
#         yourdata= [{"likes": 10, "comments": 0}, {"likes": 4, "comments": 23}]
#         results = YourSerializer(yourdata, many=True).data
#         return Response(results)
# class EventCreationSerializer(serializers.Serializer):
#     """Define fields here"""
#     pfm_id = serializers.IntegerField(max_length=2)
#     city_id=serializers.CharField(max_length=3)
#     day_id=serializers.CharField(max_length=250)
#     db_id = serializers.IntegerField(max_length=250)
#     process_id = serializers.IntegerField(max_length=250)
#     object_id = serializers.CharField(max_length=250)
#     instance_id =serializers.CharField(max_length=250)
#     context = serializers.CharField(max_length=250)
#     rule = serializers.CharField(max_length=250)
#     login_id = serializers.CharField(max_length=250)
#     document_id = serializers.CharField(max_length=250)
#     status_id = serializers.CharField(max_length=250)
#     IP = serializers.IntegerField(max_length=250)
#     session_id = serializers.CharField(max_length=250)
#     location = serializers.CharField(max_length=250)
#     regtime = serializers.DateField(max_length=250)
#     datatype = serializers.CharField(max_length=250)