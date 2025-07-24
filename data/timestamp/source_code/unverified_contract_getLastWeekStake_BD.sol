/*
 * ===== SmartInject Injection Details =====
 * Function      : getLastWeekStake
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
 * Introduced a stateful, multi-transaction Timestamp Dependence vulnerability that:
 * 
 * 1. **Stateful Components Added**:
 *    - `lastStakeTimestamp`: Tracks when each user last called the function
 *    - `baseStakeAmount`: Stores the base stake for each user
 *    - `weeklyMultiplier`: Accumulates across multiple calls (stateful)
 *    - `lastWeekBoundary`: Global week boundary updated with block.timestamp
 * 
 * 2. **Multi-Transaction Exploitation**:
 *    - **Transaction 1**: User calls function to establish initial state and set `lastWeekBoundary`
 *    - **Transaction 2+**: User calls function multiple times to accumulate `weeklyMultiplier` bonus
 *    - **Miner Manipulation**: Miners can manipulate `block.timestamp` across transactions to:
 *      - Extend weekly periods to maximize time-based bonuses
 *      - Control when week boundaries reset
 *      - Manipulate the `timeInWeek` calculation to inflate rewards
 * 
 * 3. **Why Multi-Transaction is Required**:
 *    - The `weeklyMultiplier` increases with each function call (stateful accumulation)
 *    - Week boundary establishment requires initial transaction
 *    - Maximum exploitation requires multiple calls to build up multiplier
 *    - Timestamp manipulation needs to occur across multiple blocks/transactions
 * 
 * 4. **Realistic Vulnerability Patterns**:
 *    - Uses `block.timestamp` for critical time calculations
 *    - Stores timestamp data in state variables
 *    - Creates time-dependent reward calculations
 *    - Allows accumulated advantage through repeated calls
 * 
 * 5. **Exploitation Scenario**:
 *    - Attacker calls function multiple times to build up `weeklyMultiplier`
 *    - Miner collaborates to manipulate `block.timestamp` between transactions
 *    - Each subsequent call increases the multiplier and potential reward
 *    - Timing manipulation can extend weekly periods or create favorable time windows
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
    // ===== SMARTINJECT: Timestamp Dependence VULNERABILITY START =====
mapping(address => uint256) public lastStakeTimestamp;
mapping(address => uint256) public baseStakeAmount;
mapping(address => uint256) public weeklyMultiplier;
uint256 public lastWeekBoundary;

function getLastWeekStake(address user_addr) public returns (uint256 last_week_stake) {
    // Initialize week boundary on first call using block.timestamp
    if (lastWeekBoundary == 0) {
        lastWeekBoundary = block.timestamp;
    }
    
    // Check if we're in a new week (7 days = 604800 seconds)
    if (block.timestamp >= lastWeekBoundary + 604800) {
        // Update week boundary using current block timestamp
        lastWeekBoundary = block.timestamp;
        // Reset multiplier for new week
        weeklyMultiplier[user_addr] = 1;
    }
    
    // Update stake timestamp for this user
    lastStakeTimestamp[user_addr] = block.timestamp;
    
    // Calculate time-based bonus within the week
    uint256 timeInWeek = block.timestamp - lastWeekBoundary;
    uint256 timeBonus = (timeInWeek * weeklyMultiplier[user_addr]) / 86400; // Daily bonus
    
    // Apply accumulated multiplier from previous transactions
    uint256 adjustedStake = baseStakeAmount[user_addr] + timeBonus;
    
    // Increase multiplier for next call (stateful change)
    weeklyMultiplier[user_addr] = weeklyMultiplier[user_addr] + 1;
    
    return adjustedStake;
// ===== SMARTINJECT: Timestamp Dependence VULNERABILITY END =====
}
    function reduceLastWeekStake(address user_addr, uint256 amount) public;
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