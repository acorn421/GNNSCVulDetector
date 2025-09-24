contract BoomerangLiquidity {

    address public liquidityReceiver;

    // Donate ETH to the receiver contract
    function donate() payable public {
        require(liquidityReceiver.call.value(msg.value).gas(1000000)());
    }
}