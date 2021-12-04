import websocket


def on_message(ws, message):
    print(message)


def on_error(ws, error):
    print("WebSocket error:", error)


# def on_close(ws, close_status_code, close_msg):
#     print("### closed ###")


def on_open(ws):
    ws.send("Message From Client")


if __name__ == "__main__":
    websocket.enableTrace(True)
    ws = websocket.WebSocketApp(
        "ws://localhost:8080", on_open=on_open, on_message=on_message, on_error=on_error
    )

    ws.run_forever()
