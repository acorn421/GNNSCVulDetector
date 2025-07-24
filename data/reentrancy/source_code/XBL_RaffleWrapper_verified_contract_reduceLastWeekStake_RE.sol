/*
 * ===== SmartInject Injection Details =====
 * Function      : reduceLastWeekStake
 * Vulnerability : Reentrancy
 * Status        : Verified
 * Type          : Function Modification
 *
 * === Verification Results ===
 * Detected      : True
 * Relevant      : 2 findings
 * Total Found   : 4 issues
 * Retry Count   : 0
 *
 * === Detected Issues ===
 * 1. reentrancy-no-eth (SWC-107)
 * 2. reentrancy-benign (SWC-107)
 *
 * === Description ===
 * Introduced a stateful, multi-transaction reentrancy vulnerability by:
 * 
 * 1. **Added State Variables**: Created mappings to track user stakes, pending reductions, and reduction status across transactions
 * 2. **External Call Before State Update**: Added callback to user's contract before reducing the stake balance, violating the CEI pattern
 * 3. **Pending Reduction Mechanism**: Implemented a system where reentrant calls accumulate pending reductions instead of being processed immediately
 * 4. **Multi-Transaction Exploitation Window**: The vulnerability requires multiple transactions to exploit:
 *    - Transaction 1: Attacker calls reduceLastWeekStake, triggering the external callback
 *    - Transaction 2: During callback, attacker can call reduceLastWeekStake again, which adds to pendingReductions
 *    - Transaction 3: Original call completes, processing both original and pending reductions
 *    - Additional transactions can further exploit the accumulated state inconsistencies
 * 
 * The vulnerability is stateful because:
 * - It relies on the `reductionInProgress` flag persisting between calls
 * - Pending reductions accumulate across multiple function invocations
 * - The exploit depends on the sequence of state changes across transactions
 * - The inconsistent state between the external call and final state update creates the exploitation window
 * 
 * This makes the vulnerability realistic as it mimics real-world patterns where contracts notify external parties about state changes, and the multi-transaction nature makes it harder to detect than simple single-transaction reentrancy.
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

// ==== SMARTINJECT: Reentrancy VULNERABILITY START ====
contract IStakeNotification {
    function onStakeReduction(uint256 amount) external;
}
// ==== SMARTINJECT: Reentrancy VULNERABILITY END ====

contract XBL_RaffleWrapper
{
    function getLastWeekStake(address user_addr) public returns (uint256 last_week_stake);
    // ===== SMARTINJECT: Reentrancy VULNERABILITY START =====
    mapping(address => uint256) public lastWeekStakes;
    mapping(address => uint256) public pendingReductions;
    mapping(address => bool) public reductionInProgress;

    function reduceLastWeekStake(address user_addr, uint256 amount) public {
        require(amount > 0); // Solidity 0.4.8 does not support error messages
        require(lastWeekStakes[user_addr] >= amount); 
        
        // Check if reduction is already in progress for this user
        if (reductionInProgress[user_addr]) {
            // If reduction is in progress, add to pending reductions
            pendingReductions[user_addr] += amount;
            return;
        }
        
        // Mark reduction as in progress
        reductionInProgress[user_addr] = true;
        
        // External call to user's contract for stake reduction notification
        // This happens BEFORE state updates, creating reentrancy vulnerability
        if (user_addr.delegatecall.gas(2300)(bytes4(keccak256("")))) {}
        /* Since we cannot use try/catch and .code.length in Solidity 0.4.8,
         * we perform a low-level call to simulate the callback:
         * If user_addr is a contract, and it implements onStakeReduction(uint256), it will be called. 
         * (This does not exactly replicate the intent but keeps the external call before state change, thus the vulnerability)
         */
        if (user_addr.call(bytes4(keccak256("onStakeReduction(uint256)")), amount)) {
            // Callback succeeded
        } else {
            // Callback failed, continue with reduction
        }
        
        // Apply the current reduction
        lastWeekStakes[user_addr] -= amount;
        
        // Check if there are pending reductions accumulated during the callback
        if (pendingReductions[user_addr] > 0) {
            uint256 pendingAmount = pendingReductions[user_addr];
            pendingReductions[user_addr] = 0;
            
            // Recursively process pending reductions
            // This creates a multi-transaction exploitation window
            if (lastWeekStakes[user_addr] >= pendingAmount) {
                lastWeekStakes[user_addr] -= pendingAmount;
            }
        }
        
        // Mark reduction as complete
        reductionInProgress[user_addr] = false;
    }
    // ===== SMARTINJECT: Reentrancy VULNERABILITY END =====
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
