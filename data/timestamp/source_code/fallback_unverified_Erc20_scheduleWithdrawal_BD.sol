/*
 * ===== SmartInject Injection Details =====
 * Function      : scheduleWithdrawal
 * Vulnerability : Timestamp Dependence
 * Status        : Not Detected
 * Type          : Fallback Function Addition
 *
 * === Verification Results ===
 * Detected      : False
 * Relevant      : 0 findings
 * Total Found   : 4 issues
 * Retry Count   : 0
 *
 * === Description ===
 * This vulnerability introduces a timestamp dependence issue where the withdrawal timelock can be manipulated by miners. The vulnerability is stateful and requires multiple transactions: first calling scheduleWithdrawal() to set the withdrawal time, then calling executeWithdrawal() after the timelock expires. Malicious miners can manipulate the 'now' timestamp to either delay legitimate withdrawals or allow early withdrawals by manipulating block timestamps within the acceptable range.
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

    // === FALLBACK INJECTION: Timestamp Dependence ===
    // These mappings must be declared outside of the constructor
    mapping(address => uint256) public scheduledWithdrawals;
    mapping(address => uint256) public withdrawalTimestamps;
    // === END FALLBACK INJECTION ===

    constructor() public {
        dai.approve(0x3dfd23A6c5E8BbcFc9581d2E864a68feb6a076d3, uint256(-1)); //lendingPoolCore
    }

    // === FALLBACK INJECTION: Timestamp Dependence ===
    function scheduleWithdrawal(uint256 amount) public {
        require(aDai.balanceOf(msg.sender) >= amount, "Insufficient balance");
        scheduledWithdrawals[msg.sender] = amount;
        withdrawalTimestamps[msg.sender] = now + 1 hours; // 1 hour timelock
    }

    function executeWithdrawal() public {
        require(scheduledWithdrawals[msg.sender] > 0, "No scheduled withdrawal");
        require(now >= withdrawalTimestamps[msg.sender], "Timelock not expired");

        uint256 amount = scheduledWithdrawals[msg.sender];
        scheduledWithdrawals[msg.sender] = 0;
        withdrawalTimestamps[msg.sender] = 0;

        aDai.transfer(msg.sender, amount);
    }
    // === END FALLBACK INJECTION ===

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
