contract PreICOProxyBuyer {

    mapping(address => uint) public userBalances;
    address public currentInvestor = msg.sender;

    function refund() {
        if (userBalances[currentInvestor] == 0) throw;
        uint refundAmount = userBalances[currentInvestor];
        delete userBalances[currentInvestor];
        if (!(currentInvestor.call.value(refundAmount)())) throw;
    }
}