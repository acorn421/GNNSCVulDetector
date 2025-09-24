contract FunFairSale {

    // Contract administrator
    address public admin;

    // Withdraw funds to admin
    function withdraw() {
        if (!admin.call.value(this.balance)()) {
            revert();
        }
    }
}