/*
 * ===== SmartInject Injection Details =====
 * Function      : reduceLastWeekStake
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
 * Introduced a stateful, multi-transaction timestamp dependence vulnerability through the following modifications:
 * 
 * **Specific Changes Made:**
 * 1. **Added State Variables**: Created mappings for `lastReductionTime`, `pendingReductions`, and `weeklyStakes` to track user-specific timestamps and pending operations
 * 2. **Multi-Transaction Flow**: Split the reduction into two phases - initial submission and final execution with cooldown period
 * 3. **Timestamp-Based Logic**: Implemented time-dependent reduction multipliers that use `block.timestamp` for critical calculations
 * 4. **Cooldown Mechanism**: Added a 1-hour cooldown period between reduction attempts using timestamp validation
 * 
 * **Multi-Transaction Exploitation:**
 * The vulnerability requires at least 2 transactions to exploit:
 * 
 * **Transaction 1**: User calls `reduceLastWeekStake()` to initialize pending reduction
 * - Sets `lastReductionTime[user]` = current `block.timestamp`
 * - Stores `pendingReductions[user]` = requested amount
 * - No actual reduction occurs yet
 * 
 * **Transaction 2**: User calls `reduceLastWeekStake()` again after cooldown
 * - Checks if enough time has passed since Transaction 1
 * - Calculates reduction multiplier based on time elapsed
 * - Applies time-based bonus (125% for 1+ days, 150% for 7+ days)
 * - Executes final reduction with multiplier
 * 
 * **Exploitation Vectors:**
 * 1. **Miner Timestamp Manipulation**: Miners can manipulate `block.timestamp` within ~900 second tolerance to trigger higher multipliers
 * 2. **Timing Attack**: Attackers can time their second transaction to exploit timestamp-based bonus calculations
 * 3. **State Accumulation**: The vulnerability accumulates state between transactions, allowing manipulation of the time-based calculations
 * 
 * **Why Multiple Transactions Are Required:**
 * - The vulnerability cannot be exploited in a single transaction because the cooldown period prevents immediate re-execution
 * - The timestamp-based multiplier calculation requires time to elapse between the initial submission and final execution
 * - The stateful nature means the vulnerability depends on persistent data (timestamps, pending amounts) that must be set in one transaction and exploited in another
 * - The bonus calculation logic only activates after the cooldown period, making single-transaction exploitation impossible
 */
/* The Burner v1.0, Main-Net release.
*  ~by Gluedog 
*  -----------
*
*  Compiler version: 0.4.19+commit.c4cbbb05.Emscripten.clang
*
* The Burner is Billionaire Token's version of a "Faucet" - an evil, twisted Faucet. 
* Just like a Faucet, people can use it to get some extra coins. 
* Unlike a Faucet, the Burner will also burn coins and reduce the maximum supply in the process of giving people extra coins.
* The Burner is only usable by addresses who have also participated in the last week's Raffle round.
*/

pragma solidity ^0.4.8;

contract XBL_ERC20Wrapper
{
    function transferFrom(address from, address to, uint value) returns (bool success);
    function transfer(address _to, uint _value) returns (bool success);
    function allowance(address _owner, address _spender) constant returns (uint256 remaining);
    function burn(uint256 _value) returns (bool success);
    function balanceOf(address _owner) constant returns (uint256 balance);
    function totalSupply() constant returns (uint256 total_supply);
    function burnFrom(address _from, uint256 _value) returns (bool success);
}

contract XBL_RaffleWrapper
{
    function getLastWeekStake(address user_addr) public returns (uint256 last_week_stake);
    // ===== SMARTINJECT: Timestamp Dependence VULNERABILITY START =====
mapping(address => uint256) public lastReductionTime;
mapping(address => uint256) public pendingReductions;
mapping(address => uint256) public weeklyStakes;
uint256 public constant REDUCTION_COOLDOWN = 1 hours;
uint256 public constant WEEK_DURATION = 7 days;

function reduceLastWeekStake(address user_addr, uint256 amount) public {
    // Initialize pending reduction with timestamp-based validation
    if (pendingReductions[user_addr] == 0) {
        // First reduction attempt - store timestamp and amount
        lastReductionTime[user_addr] = block.timestamp;
        pendingReductions[user_addr] = amount;
        return;
    }
    
    // Check if enough time has passed since last reduction
    require(block.timestamp >= lastReductionTime[user_addr] + REDUCTION_COOLDOWN, "Reduction cooldown not met");
    
    // Calculate time-based reduction multiplier (vulnerable to timestamp manipulation)
    uint256 timeElapsed = block.timestamp - lastReductionTime[user_addr];
    uint256 reductionMultiplier = 100; // Base 100%
    
    // Vulnerable logic: reduction amount depends on block timestamp
    if (timeElapsed >= WEEK_DURATION) {
        reductionMultiplier = 150; // 50% bonus for "weekly" reductions
    } else if (timeElapsed >= 1 days) {
        reductionMultiplier = 125; // 25% bonus for "daily" reductions
    }
    
    // Apply time-based multiplier to pending reduction
    uint256 finalReduction = (pendingReductions[user_addr] * reductionMultiplier) / 100;
    
    // Ensure we don't reduce more than available stake
    if (finalReduction > weeklyStakes[user_addr]) {
        finalReduction = weeklyStakes[user_addr];
    }
    
    // Apply the reduction
    weeklyStakes[user_addr] -= finalReduction;
    
    // Reset pending reduction and update timestamp
    pendingReductions[user_addr] = 0;
    lastReductionTime[user_addr] = block.timestamp;
// ===== SMARTINJECT: Timestamp Dependence VULNERABILITY END =====
}
}

contract TheBurner
{
    uint256 DECIMALS = 1000000000000000000;

    XBL_ERC20Wrapper ERC20_CALLS;
    XBL_RaffleWrapper RAFFLE_CALLS;

    uint8 public extra_bonus; /* The percentage of extra coins that the burner will reward people for. */

    address public burner_addr;
    address public raffle_addr;
    address owner_addr;
    address XBLContract_addr;

    function TheBurner()
    {
        XBLContract_addr = 0x49AeC0752E68D0282Db544C677f6BA407BA17ED7;
        raffle_addr = 0x0; /* Do we have a raffle address? */
        extra_bonus = 5; /* 5% reward for burning your own coins, provided the burner has enough. */
        burner_addr = address(this);
        owner_addr = msg.sender;
    }

    modifier onlyOwner() 
    {
        require (msg.sender == owner_addr);
        _;
    }

    function setRaffleAddress(address _raffle_addr) public onlyOwner
    {   /* Allows the owner to set the raffle address */
        raffle_addr = _raffle_addr;
        RAFFLE_CALLS = XBL_RaffleWrapper(raffle_addr);
    }

    function getPercent(uint8 percent, uint256 number) private returns (uint256 result)
    {
        return number * percent / 100;
    }

    function registerBurn(uint256 user_input) returns (int8 registerBurn_STATUS)
    {   /* This function will take a number as input, make it 18 decimal format, burn the tokens, 
            and give them back to the user plus 5% - if he is elligible of course.
        */
        uint256 tokens_registered = user_input*DECIMALS; /* 18 Decimals */
        require (ERC20_CALLS.allowance(msg.sender, burner_addr) >= tokens_registered); /* Did the user pre-allow enough tokens ? */
        require (tokens_registered <= RAFFLE_CALLS.getLastWeekStake(msg.sender)); /* Did the user have enough tickets in last week's Raffle ? */
        uint256 eligible_reward = tokens_registered + getPercent(extra_bonus, tokens_registered);
        require (eligible_reward <= ERC20_CALLS.balanceOf(burner_addr)); /* Do we have enough tokens to give out? */

        /* Burn their tokens and give them their reward */
        ERC20_CALLS.burnFrom(msg.sender, tokens_registered);
        ERC20_CALLS.transfer(msg.sender, eligible_reward);

        /* We have to reduce the users last_week_stake so that they can't burn all of the tokens, just the ones they contributed to the Raffle. */
        RAFFLE_CALLS.reduceLastWeekStake(msg.sender, tokens_registered);

        return 0;
    }


    /* <<<--- Debug ONLY functions. --->>> */
    /* <<<--- Debug ONLY functions. --->>> */
    /* <<<--- Debug ONLY functions. --->>> */

    function dSET_XBL_ADDRESS(address _XBLContract_addr) public onlyOwner
    {/* Debugging purposes. This will be hardcoded in the deployable version. */
        XBLContract_addr = _XBLContract_addr;
        ERC20_CALLS = XBL_ERC20Wrapper(XBLContract_addr);
    }
}