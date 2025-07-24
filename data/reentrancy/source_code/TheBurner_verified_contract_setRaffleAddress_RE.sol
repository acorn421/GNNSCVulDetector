/*
 * ===== SmartInject Injection Details =====
 * Function      : setRaffleAddress
 * Vulnerability : Reentrancy
 * Status        : Verified
 * Type          : Function Modification
 *
 * === Verification Results ===
 * Detected      : True
 * Relevant      : 2 findings
 * Total Found   : 3 issues
 * Retry Count   : 0
 *
 * === Detected Issues ===
 * 1. reentrancy-no-eth (SWC-107)
 * 2. reentrancy-benign (SWC-107)
 *
 * === Description ===
 * This modification introduces a stateful, multi-transaction reentrancy vulnerability by adding external calls to raffle contracts before and after state updates. The vulnerability requires multiple transactions to exploit:
 * 
 * **Specific Changes Made:**
 * 1. Added external call to old raffle contract (`onRaffleAddressChange`) BEFORE updating raffle_addr
 * 2. Added external call to new raffle contract (`onRaffleRegistered`) AFTER updating state
 * 3. Both calls allow the external contracts to call back into TheBurner during state transitions
 * 
 * **Multi-Transaction Exploitation Path:**
 * 1. **Transaction 1**: Attacker deploys malicious raffle contract that implements callback functions
 * 2. **Transaction 2**: Owner calls setRaffleAddress() with malicious contract address
 * 3. **During Transaction 2**: External calls trigger reentrancy, but state is inconsistent - raffle_addr may be updated but RAFFLE_CALLS still points to old contract
 * 4. **Transaction 3+**: Attacker exploits the inconsistent state where raffle_addr and RAFFLE_CALLS point to different contracts
 * 
 * **Why Multi-Transaction is Required:**
 * - Initial setup requires deploying the malicious contract (Transaction 1)
 * - The reentrancy creates inconsistent state that persists across transactions
 * - Exploitation requires subsequent calls to functions like registerBurn() that depend on both raffle_addr and RAFFLE_CALLS
 * - The vulnerability leverages the state inconsistency that exists between the two external calls
 * 
 * **State Persistence Factor:**
 * The vulnerability creates a persistent state inconsistency where raffle_addr and RAFFLE_CALLS can point to different contracts between transactions, enabling complex exploitation scenarios that require multiple function calls to fully leverage.
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
    // Added stub to fix compile error: onRaffleAddressChange()
    function onRaffleAddressChange(address _raffle_addr) public;
    // Added stub to fix compile error: onRaffleRegistered()
    function onRaffleRegistered(address burner_addr) public;
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

    constructor() public
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
// ===== SMARTINJECT: Reentrancy VULNERABILITY START =====
{   /* Allows the owner to set the raffle address */
    // Notify old raffle contract before changing address
    if (raffle_addr != address(0)) {
        XBL_RaffleWrapper(raffle_addr).onRaffleAddressChange(_raffle_addr);
    }
    
    raffle_addr = _raffle_addr;
    RAFFLE_CALLS = XBL_RaffleWrapper(raffle_addr);
    
    // Initialize new raffle contract with callback
    if (_raffle_addr != address(0)) {
        XBL_RaffleWrapper(_raffle_addr).onRaffleRegistered(address(this));
    }
}
// ===== SMARTINJECT: Reentrancy VULNERABILITY END =====

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
