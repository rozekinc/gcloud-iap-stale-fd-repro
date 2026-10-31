FROM gcr.io/google.com/cloudsdktool/google-cloud-cli:590.0.1-alpine
COPY iap_tunnel_lightweight_websocket.py /google-cloud-sdk/lib/googlecloudsdk/api_lib/compute/iap_tunnel_lightweight_websocket.py
RUN rm -f /google-cloud-sdk/lib/googlecloudsdk/api_lib/compute/__pycache__/iap_tunnel_lightweight_websocket.* \
 && chmod 644 /google-cloud-sdk/lib/googlecloudsdk/api_lib/compute/iap_tunnel_lightweight_websocket.py
