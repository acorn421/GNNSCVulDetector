contract ICOBuyer {

    address public tokenSale;

    // Purchase tokens by sending all contract balance
    function purchaseTokens() external {
        require(tokenSale.call.value(address(this).balance)());
    }
}