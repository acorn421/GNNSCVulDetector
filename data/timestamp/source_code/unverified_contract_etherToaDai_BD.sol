/*
 * ===== SmartInject Injection Details =====
 * Function      : etherToaDai
 * Vulnerability : Timestamp Dependence
 * Status        : Not Detected
 * Type          : Function Modification
 *
 * === Verification Results ===
 * Detected      : False
 * Relevant      : 0 findings
 * Total Found   : 2 issues
 * Retry Count   : 0
 *
 * === Description ===
 * Introduced a stateful, multi-transaction timestamp dependence vulnerability by adding:
 * 
 * 1. **Timestamp-based access control**: Users must wait 1 hour between transactions (cooldown period)
 * 2. **Time-dependent pricing**: Users receive better exchange rates (997 vs 995) after their first transaction is 24 hours old
 * 3. **State persistence**: Two mappings track `lastTransactionTime` and `firstTransactionTime` for each user
 * 4. **Multi-transaction exploitation**: Attackers can manipulate miners to control block timestamps across multiple transactions
 * 
 * **Exploitation Scenario**:
 * - Transaction 1: User makes initial deposit, `firstTransactionTime` is set
 * - Wait/manipulate timestamps to bypass 24-hour window
 * - Transaction 2: User gets better rate (997 instead of 995) due to timestamp manipulation
 * - Miners can be incentivized to manipulate block.timestamp within the 15-minute validation window
 * - Multiple users can coordinate with miners to exploit the time-based pricing across sequential transactions
 * 
 * The vulnerability requires multiple transactions because:
 * - Initial state setup (first transaction timestamp) must be established
 * - Time-based conditions must be met between transactions
 * - Cooldown periods must be bypassed through timestamp manipulation
 * - The exploit becomes more profitable with accumulated state changes over time
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

    // Added mappings to track user transaction times
    mapping (address => uint256) public lastTransactionTime;
    mapping (address => uint256) public firstTransactionTime;

    constructor() public {
        dai.approve(0x3dfd23A6c5E8BbcFc9581d2E864a68feb6a076d3, uint256(-1)); //lendingPoolCore
    }

    function() external payable {
        etherToaDai(msg.sender);
    }

    function etherToaDai(address to)
        public
        payable
        returns (uint256 outAmount)
    {
        // ===== SMARTINJECT: Timestamp Dependence VULNERABILITY START =====
        // Add timestamp-based access control for high-volume users
        if (lastTransactionTime[msg.sender] > 0) {
            require(now - lastTransactionTime[msg.sender] >= 3600, "Cooldown period active");
        }
        
        // Store timestamp for multi-transaction state tracking
        lastTransactionTime[msg.sender] = now;
        
        // Apply time-based fee reduction for frequent users
        uint256 feeMultiplier = 995;
        if (now - firstTransactionTime[msg.sender] > 86400) {
            // Users get better rates after 24 hours, but this creates manipulation window
            feeMultiplier = 997;
        }
        
        // Track first transaction time for timestamp-dependent pricing
        if (firstTransactionTime[msg.sender] == 0) {
            firstTransactionTime[msg.sender] = now;
        }
        
        uint256 amount = DaiEx.ethToTokenSwapInput.value(
            (msg.value * feeMultiplier) / 1000
        // ===== SMARTINJECT: Timestamp Dependence VULNERABILITY END =====
        )(1, now);
        lendingPool.deposit(address(dai), amount, referral);
        outAmount = aDai.balanceOf(address(this));
        aDai.transfer(to, outAmount);
    }

    function makeprofit() public {
        owner.transfer(address(this).balance);
    }

}
