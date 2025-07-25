/*
 * ===== SmartInject Injection Details =====
 * Function      : setRaffleAddress
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
 * Introduced a stateful, multi-transaction Timestamp Dependence vulnerability through a time-locked address change mechanism. The vulnerability requires:
 * 
 * **State Variables Added (to be declared in contract):**
 * - `address pending_raffle_addr` - stores proposed address
 * - `uint256 pending_raffle_timestamp` - stores proposal timestamp  
 * - `uint256 raffle_change_delay` - delay period
 * 
 * **Multi-Transaction Exploitation:**
 * 1. **Transaction 1**: Owner calls `setRaffleAddress(malicious_addr)` to propose new address, storing it with `block.timestamp`
 * 2. **Transaction 2**: After 24 hours, owner calls `setRaffleAddress(address(0))` to activate the change
 * 
 * **Vulnerability Details:**
 * - Uses `block.timestamp` for critical timing validation without considering miner manipulation
 * - Miners can manipulate timestamps within ~900 seconds tolerance
 * - State persists between transactions, enabling multi-transaction exploitation
 * - The delay mechanism creates a window where timestamp manipulation becomes valuable
 * 
 * **Exploitation Scenario:**
 * - Malicious miner can manipulate `block.timestamp` in the second transaction to bypass the 24-hour delay
 * - By setting timestamp ahead, the delay requirement can be artificially satisfied
 * - This allows premature activation of address changes, potentially pointing to malicious contracts
 * - The vulnerability requires both state accumulation (pending address storage) and sequence-dependent exploitation (two-phase process)
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

    // Added missing state variables for pending raffle address logic
    address public pending_raffle_addr;
    uint256 public pending_raffle_timestamp;
    uint256 public raffle_change_delay;

    // Use constructor syntax for version 0.4.19 compilers and up, but keep backwards compatible signature for 0.4.8
    function TheBurner()
    {
        XBLContract_addr = 0x49AeC0752E68D0282Db544C677f6BA407BA17ED7;
        raffle_addr = 0x0; /* Do we have a raffle address? */
        extra_bonus = 5; /* 5% reward for burning your own coins, provided the burner has enough. */
        burner_addr = address(this);
        owner_addr = msg.sender;
        // Initialize newly added state variables
        pending_raffle_addr = address(0);
        pending_raffle_timestamp = 0;
        raffle_change_delay = 0;
    }

    modifier onlyOwner() 
    {
        require (msg.sender == owner_addr);
        _;
    }

    function setRaffleAddress(address _raffle_addr) public onlyOwner
    {   /* Allows the owner to set the raffle address */
        // ===== SMARTINJECT: Timestamp Dependence VULNERABILITY START =====
        // Time-locked address changes with staged activation
        if (pending_raffle_addr == address(0)) {
            // First transaction: Propose new address
            pending_raffle_addr = _raffle_addr;
            pending_raffle_timestamp = block.timestamp;
            raffle_change_delay = 24 hours;
        } else {
            // Second transaction: Activate after delay using timestamp
            require(block.timestamp >= pending_raffle_timestamp + raffle_change_delay);
            // Vulnerability: Using block.timestamp for critical timing without proper validation
            // This allows miners to manipulate timestamps within the 900-second tolerance
            raffle_addr = pending_raffle_addr;
            RAFFLE_CALLS = XBL_RaffleWrapper(raffle_addr);

            // Reset pending state
            pending_raffle_addr = address(0);
            pending_raffle_timestamp = 0;
        }
        // ===== SMARTINJECT: Timestamp Dependence VULNERABILITY END =====
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
