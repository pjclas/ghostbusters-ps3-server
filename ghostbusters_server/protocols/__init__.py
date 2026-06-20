"""Protocol registration. Each protocol module exposes register(dispatcher)
that adds its (proto, method) entries to the dispatch table."""

from . import account_management, authentication, game, matchmaking, nat, secure_connection


def register_all(dispatcher) -> None:
    authentication.register(dispatcher)
    secure_connection.register(dispatcher)
    account_management.register(dispatcher)
    matchmaking.register(dispatcher)
    nat.register(dispatcher)
    game.register(dispatcher)
