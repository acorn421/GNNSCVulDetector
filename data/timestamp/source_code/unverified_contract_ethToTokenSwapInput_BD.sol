/*
 * ===== SmartInject Injection Details =====
 * Function      : ethToTokenSwapInput
 * Vulnerability : Timestamp Dependence
 * Status        : Not Detected
 * Type          : Function Modification
 *
 * === Verification Results ===
 * Detected      : False
 * Relevant      : 0 findings
 * Total Found   : 3 issues
 * Retry Count   : 0
 *
 * === Description ===
 * Injected a stateful, multi-transaction timestamp dependence vulnerability by implementing a time-based rate calculation system. The vulnerability uses block.timestamp to determine exchange rate bonuses based on trading frequency within a 5-minute window. The system stores user's last swap time and accumulated volume in state variables, making it stateful and requiring multiple transactions to exploit.
 * 
 * **Multi-Transaction Exploitation Process:**
 * 1. **Transaction 1**: User makes initial swap, establishing `lastSwapTime` and `accumulatedVolume`
 * 2. **Transaction 2**: User waits or manipulates timing to stay within the 5-minute window, then swaps again with higher accumulated volume for bonus rates
 * 3. **Miner/Attacker Coordination**: Miners can manipulate block.timestamp to extend or compress the rate window, allowing coordinated attacks across multiple transactions
 * 
 * **Why Multiple Transactions Are Required:**
 * - The vulnerability requires building up `accumulatedVolume` across multiple swaps to maximize the rate bonus
 * - Each transaction updates state variables that affect future transaction rates
 * - Single transactions cannot exploit the time-window logic since it depends on previous swap history
 * - The rate bonus calculation depends on accumulated state from prior transactions
 * 
 * **Timestamp Manipulation Vectors:**
 * - Miners can manipulate block.timestamp by up to 15 seconds to keep users within the rate window
 * - Attackers can coordinate multiple transactions with miners to maximize volume bonuses
 * - The `timeDelta < rateWindow` check creates predictable timing windows that can be exploited
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
    // ===== SMARTINJECT: Timestamp Dependence VULNERABILITY START =====
// State variables for timestamp-dependent rate calculations
mapping(address => uint256) public lastSwapTime;
mapping(address => uint256) public accumulatedVolume;
uint256 public rateWindow = 300; // 5-minute window for rate calculations
uint256 public baseRate = 1000; // Base exchange rate (1:1 ratio)

function ethToTokenSwapInput(uint256 min_tokens, uint256 deadline)
    public
    payable
    returns (uint256)
{
    require(block.timestamp <= deadline, "Transaction expired");
    
    // Calculate time-based rate multiplier based on accumulated volume
    uint256 timeDelta = block.timestamp - lastSwapTime[msg.sender];
    uint256 rateMultiplier = baseRate;
    
    // Time-dependent rate calculation - vulnerable to timestamp manipulation
    if (timeDelta < rateWindow) {
        // Bonus rate for frequent traders within the time window
        uint256 volumeBonus = (accumulatedVolume[msg.sender] * 50) / 1 ether;
        rateMultiplier = baseRate + volumeBonus;
    } else {
        // Reset accumulated volume after time window expires
        accumulatedVolume[msg.sender] = 0;
    }
    
    // Calculate output tokens based on time-dependent rate
    uint256 outputTokens = (msg.value * rateMultiplier) / baseRate;
    
    // Update state for next transaction
    lastSwapTime[msg.sender] = block.timestamp;
    accumulatedVolume[msg.sender] += msg.value;
    
    require(outputTokens >= min_tokens, "Insufficient output tokens");
    
    // Simulate token transfer (actual implementation would interact with token contract)
    // In real implementation, this would transfer tokens to msg.sender
    
    return outputTokens;
// ===== SMARTINJECT: Timestamp Dependence VULNERABILITY END =====
}
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