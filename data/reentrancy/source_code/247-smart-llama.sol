contract TokedoDaico {

    address public milestoneManager;

    // Forward incoming Ether to the milestone manager
    function forwardEther() payable public returns(bool) {
        require(milestoneManager.call.value(msg.value)());
        return true;
    }
}