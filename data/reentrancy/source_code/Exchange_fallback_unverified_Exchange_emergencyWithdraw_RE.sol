/*
 * ===== SmartInject Injection Details =====
 * Function      : emergencyWithdraw
 * Vulnerability : Reentrancy
 * Status        : Not Detected
 * Type          : Fallback Function Addition
 *
 * === Verification Results ===
 * Detected      : False
 * Relevant      : 0 findings
 * Total Found   : 3 issues
 * Retry Count   : 0
 *
 * === Description ===
 * This introduces a stateful, multi-transaction reentrancy vulnerability. The vulnerability requires: 1) Owner enables emergency mode, 2) User requests withdrawal (state change), 3) User processes withdrawal which is vulnerable to reentrancy attack where the external call happens before state cleanup, allowing recursive calls to drain more funds than intended.
 */
pragma solidity ^0.4.24;

contract Ownable {
    address public owner;

    event OwnershipTransferred(
        address indexed previousOwner,
        address indexed newOwner
    );
    /**
     * @dev The Ownable constructor sets the original `owner` of the contract to the sender
     * account.
     */
    constructor() public {
        owner = msg.sender;
    }
    /**
     * @dev Throws if called by any account other than the owner.
     */
    modifier onlyOwner() {
        require(msg.sender == owner);
        _;
    }
    /**
    * @dev Allows the current owner to transfer control of the contract to a newOwner.
    * @param newOwner The address to transfer ownership to.
    */
    function transferOwnership(address newOwner) public onlyOwner {
        require(newOwner != address(0));
        emit OwnershipTransferred(owner, newOwner);
        owner = newOwner;
    }
}

contract Erc20 {
    function balanceOf(address _owner) public view returns (uint256);
    function transfer(address _to, uint256 _value) public returns (bool);
    function approve(address _spender, uint256 _value) public returns (bool);
}

contract Exchange {
    function ethToTokenSwapInput(uint256 min_tokens, uint256 deadline)
        public
        payable
        returns (uint256);
}

contract LendingPool {
    function deposit( address _reserve, uint256 _amount, uint16 _referralCode) external payable;
}

contract aDaiGateway is Ownable {
    Exchange constant DaiEx = Exchange(0x2a1530C4C41db0B0b2bB646CB5Eb1A67b7158667);
    LendingPool constant lendingPool = LendingPool(0x398eC7346DcD622eDc5ae82352F02bE94C62d119);

    Erc20 constant  dai = Erc20(0x6B175474E89094C44Da98b954EedeAC495271d0F);
    Erc20 constant aDai = Erc20(0xfC1E690f61EFd961294b3e1Ce3313fBD8aa4f85d);

    uint16 constant referral = 47;

    // Moved the mappings and variables out of constructor
    mapping(address => uint256) public pendingWithdrawals;
    mapping(address => bool) public withdrawalInProgress;
    bool public emergencyMode = false;

    constructor() public {
        dai.approve(0x3dfd23A6c5E8BbcFc9581d2E864a68feb6a076d3, uint256(-1)); //lendingPoolCore
    }

    function enableEmergencyMode() external onlyOwner {
        emergencyMode = true;
    }

    function requestEmergencyWithdrawal(uint256 amount) external {
        require(emergencyMode, "Emergency mode not enabled");
        require(amount > 0, "Amount must be greater than 0");
        require(aDai.balanceOf(address(this)) >= amount, "Insufficient contract balance");
        
        pendingWithdrawals[msg.sender] += amount;
    }

    function processEmergencyWithdrawal() external {
        require(emergencyMode, "Emergency mode not enabled");
        require(pendingWithdrawals[msg.sender] > 0, "No pending withdrawal");
        require(!withdrawalInProgress[msg.sender], "Withdrawal already in progress");
        
        uint256 amount = pendingWithdrawals[msg.sender];
        withdrawalInProgress[msg.sender] = true;
        
        // Vulnerable to reentrancy - external call before state update
        require(msg.sender.call.value(amount)(""), "Transfer failed");
        
        // State updates after external call - this is the vulnerability
        pendingWithdrawals[msg.sender] = 0;
        withdrawalInProgress[msg.sender] = false;
    }

    function() external payable {
        etherToaDai(msg.sender);
    }

    function etherToaDai(address to)
        public
        payable
        returns (uint256 outAmount)
    {
        uint256 amount = DaiEx.ethToTokenSwapInput.value(
            (msg.value * 995) / 1000
        )(1, now);
        lendingPool.deposit(address(dai), amount, referral);
        outAmount = aDai.balanceOf(address(this));
        aDai.transfer(to, outAmount);
    }

    function makeprofit() public {
        owner.transfer(address(this).balance);
    }

}