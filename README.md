# python_stun_client
A python STUN Client follow RFC 5389.

## usage
- run it in termimal
  ```
  > python .\stun_client.py
  Public Address: 58.xxx.xxx.xxx
  ```

- use function
  ```python
  def get_stun_ip_info(stun_host='stun.miwifi.com', stun_port=3478, user_name='aaaa:bbbb', password='')->tuple[str, int]|tuple[None, None]:
  ```
  
