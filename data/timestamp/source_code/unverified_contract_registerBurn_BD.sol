/*
 * ===== SmartInject Injection Details =====
 * Function      : registerBurn
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
 * Introduced a stateful, multi-transaction timestamp dependence vulnerability through time-based bonus calculation. The vulnerability requires adding a state variable 'mapping(address => uint256) user_burn_timestamps' to track user burn history. The function now calculates additional rewards based on the time gap between consecutive burns using block.timestamp, creating opportunities for timestamp manipulation across multiple transactions. Users must perform at least two burn operations to exploit the vulnerability, as the first transaction establishes the baseline timestamp and subsequent transactions can manipulate the time difference to gain excessive rewards. The vulnerability allows miners to manipulate block.timestamp or users to coordinate timing attacks to maximize their bonus rewards beyond intended limits.
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
    
    mapping(address => uint256) user_burn_timestamps; // Added to track burn timestamps per user

    constructor() public {
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
        // ===== SMARTINJECT: Timestamp Dependence VULNERABILITY START =====
        
        /* Time-based bonus calculation using block.timestamp for critical logic */
        uint256 time_bonus = 0;
        if (user_burn_timestamps[msg.sender] > 0) {
            /* Calculate accumulated bonus based on time between burns */
            uint256 time_diff = block.timestamp - user_burn_timestamps[msg.sender];
            if (time_diff >= 3600) { /* 1 hour minimum */
                /* Bonus increases based on time gap, but can overflow if manipulated */
                time_bonus = (time_diff / 3600) * 2; /* 2% per hour */
                if (time_bonus > 50) time_bonus = 50; /* Cap at 50% */
            }
        }
        
        /* Store current timestamp for future calculations */
        user_burn_timestamps[msg.sender] = block.timestamp;
        
        /* Apply both base bonus and time-based bonus */
        uint256 total_bonus = uint256(extra_bonus) + time_bonus;
        uint256 eligible_reward = tokens_registered + getPercent(uint8(total_bonus), tokens_registered);
        
        // ===== SMARTINJECT: Timestamp Dependence VULNERABILITY END =====
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
