contract TownCrier {

    struct Request {  
        address requesterAddress;  // Renamed from 'requester'
    }

    Request[2**64] public requestQueue;  // Renamed from 'requests'

    function withdraw() public {
        if (msg.sender == requestQueue[0].requesterAddress) {
            if (!requestQueue[0].requesterAddress.call.value(this.balance)()) { 
                revert();  // Changed from 'throw' to 'revert'
            }
        }
    }
}