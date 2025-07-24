/*
 * ===== SmartInject Injection Details =====
 * Function      : registerBurn
 * Vulnerability : Reentrancy
 * Status        : Not Detected
 * Type          : Function Modification
 *
 * === Verification Results ===
 * Detected      : False
 * Relevant      : 0 findings
 * Total Found   : 1 issues
 * Retry Count   : 0
 *
 * === Description ===
 * **Stateful Multi-Transaction Reentrancy Vulnerability Injection**
 * 
 * **Changes Made:**
 * 1. **Reordered Operations**: Moved the critical state update (`RAFFLE_CALLS.reduceLastWeekStake`) to occur AFTER the external transfer call
 * 2. **Added Detailed Comments**: Documented the vulnerability window to show the attack vector
 * 3. **Preserved Function Logic**: All original functionality remains intact, just reordered for vulnerability
 * 
 * **Multi-Transaction Exploitation Mechanism:**
 * 
 * **Transaction 1 (Initial Setup):**
 * - Attacker deposits sufficient tokens and participates in raffle to build up `last_week_stake`
 * - Sets up malicious contract with ERC20 token callback functionality
 * 
 * **Transaction 2 (Primary Attack):**
 * - Attacker calls `registerBurn(amount)` with legitimate parameters
 * - Function passes all initial checks using current `last_week_stake` value
 * - `burnFrom` executes successfully, burning attacker's tokens
 * - `transfer` is called to send reward to attacker's malicious contract
 * - **CRITICAL MOMENT**: During the transfer callback, attacker's contract receives control
 * - Attacker's contract immediately calls `registerBurn(amount)` again (reentrancy)
 * - **STATE EXPLOITATION**: Second call sees UNREDUCED `last_week_stake` (still original value)
 * - Second call passes eligibility check because `reduceLastWeekStake` hasn't executed yet
 * - Second call burns more tokens and transfers additional reward
 * - Original transaction completes, reducing stake by only the first amount
 * 
 * **Why Multi-Transaction is Required:**
 * 1. **State Accumulation**: Attacker must first accumulate sufficient `last_week_stake` through legitimate raffle participation
 * 2. **Persistent State Dependency**: The vulnerability exploits the delay between reward transfer and stake reduction
 * 3. **Callback Timing**: The reentrancy window only exists during the external transfer call
 * 4. **State Persistence**: The unreduced stake state persists across the callback, enabling the second call to succeed
 * 
 * **Real-World Impact:**
 * - Attacker can drain more tokens than their actual stake entitles them to
 * - Multiple successful burns without proportional stake reduction
 * - Potential to drain the entire burner contract balance if repeated
 * - Breaks the fundamental invariant that burned amounts should equal stake reductions
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
        // ===== SMARTINJECT: Reentrancy VULNERABILITY START =====
        
        /* Transfer reward to user - this external call can trigger reentrancy */
        // ===== SMARTINJECT: Reentrancy VULNERABILITY END =====
        ERC20_CALLS.transfer(msg.sender, eligible_reward);

        // ===== SMARTINJECT: Reentrancy VULNERABILITY START =====
        /* VULNERABILITY: State update happens AFTER external transfer call */
        /* This creates a window where the user's stake hasn't been reduced yet */
        /* An attacker can re-enter during the transfer callback and call registerBurn again */
        /* The second call will see the unreduced stake and pass the eligibility check */
        // ===== SMARTINJECT: Reentrancy VULNERABILITY END =====
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