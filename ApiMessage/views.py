from datetime import timezone
import datetime
from ApiMessage.models import CustomUser, GroupeConversation, Message
from ApiMessage.serializers import (
    GroupeConversationSerializer,
    MembreGroupeConversationSerializer,
    MessageSerializer,
    UserLoginSerializer,
    UserSerializer,
)
from django.contrib.auth import authenticate, login, logout
from asgiref.sync import async_to_sync
from channels.layers import get_channel_layer
from django.http import Http404
from django.shortcuts import get_object_or_404
from rest_framework import generics, status
from rest_framework.permissions import IsAuthenticated
from rest_framework.response import Response
from rest_framework.views import APIView
from rest_framework_simplejwt.tokens import RefreshToken


class RegisterView(APIView):
    serializer_class = UserSerializer

    def post(self, request):
        serializer = self.serializer_class(data=request.data)
        if serializer.is_valid():
            user = serializer.save()
            response = {
                "msg": "Vous êtes bien inscris, désormais vous devez vous connecter !",
            }
            return Response(response, status=status.HTTP_201_CREATED)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)


class LoginView(APIView):
    serializer_class = UserLoginSerializer

    def post(self, request):
        serializer = self.serializer_class(data=request.data)
        if serializer.is_valid():
            email = request.POST["username"]
            password = request.POST["password"]
            user = authenticate(request, username=email, password=password)
            if user is not None:
                login(request, user)
                user = serializer.validated_data
                refresh = RefreshToken.for_user(user)
                response = {
                    "msg": "Vous êtes bien connecté !",
                    "refresh": str(refresh),
                    "access": str(refresh.access_token),
                }
                return Response(response, status=status.HTTP_200_OK)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)


class LogoutView(APIView):
    permission_classes = [IsAuthenticated]

    def post(self, request):
        try:
            refresh_token = request.data["refresh_token"]
            token = RefreshToken(refresh_token)
            token.blacklist()
            return Response(status=status.HTTP_205_RESET_CONTENT)
        except Exception as e:
            return Response(status=status.HTTP_400_BAD_REQUEST)


class GroupeConversationList(APIView):
    permission_classes = [IsAuthenticated]

    def get(self, request):
        user = request.user
        groupe_conversation = GroupeConversation.objects.filter(user=user)
        serializer = GroupeConversationSerializer(groupe_conversation, many=True)
        return Response(serializer.data)

    def post(self, request):
        request.data["user"].append(request.user.id)
        serializer = GroupeConversationSerializer(data=request.data)
        if serializer.is_valid():
            groupe_conversation = serializer.save()
            serializer = GroupeConversationSerializer(groupe_conversation)
            return Response(serializer.data, status=201)
        return Response(serializer.errors, status=400)


class GroupeConversationDetail(APIView):
    """
    Liste tous les membres d'un groupe de conversation, 
    ajouter un nouveau membre, supprimer un membre.
    """
    permission_classes = [IsAuthenticated]

    def get(self, request, pk):
        groupe_conversation = get_object_or_404(GroupeConversation, pk=pk)
        serializer = GroupeConversationSerializer(groupe_conversation)
        return Response(serializer.data)

    def patch(self, request, pk):
        groupe_conversation = get_object_or_404(GroupeConversation, pk=pk)
        serializer = GroupeConversationSerializer(
            groupe_conversation, data=request.data, partial=True
        )
        if serializer.is_valid():
            serializer.save()
            return Response(serializer.data)
        return Response(serializer.errors, status=400)

    def delete(self, request, pk):
        groupe_conversation = get_object_or_404(GroupeConversation, pk=pk)
        groupe_conversation.delete()
        return Response(status=204)


class MembreGroupeConversationList(APIView):
    """
    Liste tous les membres d'un groupe de conversation, 
    ajouter un nouveau membre, supprimer un membre.
    """
    permission_classes = [IsAuthenticated]

    def get(self, request, groupe_conversation_id):
        groupe_conversation = get_object_or_404(
            GroupeConversation, id=groupe_conversation_id
        )
        serializer = MembreGroupeConversationSerializer(groupe_conversation)
        return Response(serializer.data)

    def post(self, request, groupe_conversation_id):
        if request.data.get("user") == []:
            return Response(
                {"message": "Le champ 'user' est vide."},
                status=status.HTTP_404_NOT_FOUND,
            )
        groupe_conversation = get_object_or_404(
            GroupeConversation, id=groupe_conversation_id
        )
        for user_id in request.data.get("user"):
            nouvel_utilisateur = CustomUser.objects.get(id=user_id)
            groupe_conversation.user.add(nouvel_utilisateur)
        groupe_conversation.save()
        serializer = MembreGroupeConversationSerializer(groupe_conversation)
        return Response(serializer.data, status=status.HTTP_201_CREATED)

    def delete(self, request, groupe_conversation_id):
        if request.data.get("user") == []:
            return Response(
                {"message": "Le champ 'user' est vide."},
                status=status.HTTP_404_NOT_FOUND,
            )
        groupe_conversation = get_object_or_404(
            GroupeConversation, id=groupe_conversation_id
        )
        for user_id in request.data.get("user"):
            nouvel_utilisateur = CustomUser.objects.get(id=user_id)
            groupe_conversation.user.remove(nouvel_utilisateur)
        groupe_conversation.save()
        serializer = MembreGroupeConversationSerializer(groupe_conversation)
        return Response(serializer.data, status=status.HTTP_201_CREATED)


class MessageList(APIView):
    permission_classes = [IsAuthenticated]

    def get(self, request, groupe_conversation_id):
        # Get messages for the given groupe_conversation_id
        messages = Message.objects.filter(groupe_conversation_id=groupe_conversation_id)
        serializer = MessageSerializer(messages, many=True)
        return Response(serializer.data)

    def post(self, request, groupe_conversation_id):
        serializer = MessageSerializer(data=request.data)
        if serializer.is_valid():
            serializer.save(
                date_creation=datetime.datetime.now(),
                groupe_conversation_id=groupe_conversation_id,
            )

            # Send message to WebSocket group
            channel_layer = get_channel_layer()
            async_to_sync(channel_layer.group_send)(
                "groupe_conversation_%s" % groupe_conversation_id,
                {"type": "chat_message", "message": serializer.data},
            )

            return Response(serializer.data, status=status.HTTP_201_CREATED)

        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

    def patch(self, request, pk):
        message = self.get_object(pk)
        serializer = MessageSerializer(message, data=request.data, partial=True)
        if serializer.is_valid():
            serializer.save()
            return Response(serializer.data)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

    def delete(self, request, pk):
        message = self.get_object(pk)
        message.delete()
        return Response(status=status.HTTP_204_NO_CONTENT)


class MessageDetail(APIView):
    permission_classes = [IsAuthenticated]

    def get_object(self, pk):
        return get_object_or_404(Message, pk=pk)

    def get(self, request, pk):
        message = self.get_object(pk)
        serializer = MessageSerializer(message)
        return Response(serializer.data)

    def put(self, request, pk):
        message = self.get_object(pk)
        serializer = MessageSerializer(message, data=request.data)
        if serializer.is_valid():
            serializer.save()
            return Response(serializer.data)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

    def delete(self, request, pk):
        message = self.get_object(pk)
        message.delete()
        return Response(status=status.HTTP_204_NO_CONTENT)
