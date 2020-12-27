#python doesn't resolve the import correctly if this is in lib.
#it's not used by the client or server, so it does not violate the
#assignment specifications

import lib.handshakes.server._client_tests as client_tests
import lib.handshakes.server._server_tests as server_tests
import lib.handshakes.server._integration_tests as integration_tests

client_tests.test_all()
server_tests.test_all()
integration_tests.test_all()
