from ApiMessage.consumers import ChatConsumer
from ApiMessage.views import (
    GroupeConversationDetail,
    GroupeConversationList,
    LoginView,
    LogoutView,
    MembreGroupeConversationList,
    MessageDetail,
    MessageList,
    RegisterView,
)
from django.urls import path, re_path

websocket_urlpatterns = [
    re_path(r'ws/chat/(?P<groupe_conversation_id>\w+)/$', ChatConsumer.as_asgi()),
]
urlpatterns = [
    path("register/", RegisterView.as_view(), name="register"),
    path("login/", LoginView.as_view(), name="login"),
    path("logout/", LogoutView.as_view(), name="logout"),
    path(
        "groupes_conversation/",
        GroupeConversationList.as_view(),
        name="groupe_conversation_list",
    ),
    path(
        "groupes_conversation/<int:pk>/",
        GroupeConversationDetail.as_view(),
        name="groupe_conversation_detail",
    ),
    path(
        "groupes_conversation/<int:groupe_conversation_id>/membres/",
        MembreGroupeConversationList.as_view(),
        name="membre_groupe_conversation_list",
    ),
    path("message/<int:groupe_conversation_id>/", MessageList.as_view(), name="message-list"),
    path("messages/<int:pk>/", MessageDetail.as_view(), name="message-detail"),
]
