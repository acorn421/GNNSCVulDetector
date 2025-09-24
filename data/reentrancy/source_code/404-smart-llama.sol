contract dumbDAO {

    mapping (address => uint) public userBalances;

    function withdraw(address recipient) returns (bool) {

        if (recipient.call.value(userBalances[msg.sender])()) {
            userBalances[msg.sender] = 0;
            return true;
        }
    }
}