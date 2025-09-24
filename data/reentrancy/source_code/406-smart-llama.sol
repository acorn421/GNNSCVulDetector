contract ReentranceExploit {

    address public targetContract;

    // Deposit funds into the specified contract
    function deposit(address _targetContract) public payable {
        targetContract = _targetContract;
        require(targetContract.call.value(msg.value)());
    }
}