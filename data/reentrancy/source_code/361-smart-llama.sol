contract Ethex {

    mapping(bytes32 => uint256) public buyOrders;

    function cancelBuyOrder(address tokenAddress, uint256 orderPrice) {
        bytes32 orderHash = sha256(tokenAddress, orderPrice, msg.sender);
        uint256 remainingBalance = buyOrders[orderHash];
        delete buyOrders[orderHash];
        if (!msg.sender.call.value(remainingBalance)()) throw;
    }
}