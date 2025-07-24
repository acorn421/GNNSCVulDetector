/*
 * ===== SmartInject Injection Details =====
 * Function      : scheduleBurn
 * Vulnerability : Timestamp Dependence
 * Status        : Not Detected
 * Type          : Fallback Function Addition
 *
 * === Verification Results ===
 * Detected      : False
 * Relevant      : 0 findings
 * Total Found   : 6 issues
 * Retry Count   : 0
 *
 * === Description ===
 * This injection adds a timestamp dependence vulnerability through a multi-transaction scheduled burn system. The vulnerability requires two separate transactions: first scheduleBurn() to set up the burn with a future timestamp, then executeBurn() to execute it. The vulnerability lies in the reliance on 'now' (block.timestamp) for both scheduling and execution timing, which miners can manipulate within bounds. Malicious miners could potentially manipulate timestamps to either prevent execution of scheduled burns or allow premature execution to gain time-based bonuses. The state persists between transactions through scheduled_burn_timestamp, scheduled_burn_amount, scheduled_burn_user, and burn_scheduled variables.
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

    // === FALLBACK INJECTION: Timestamp Dependence ===
    // This function was added as a fallback when existing functions failed injection
    uint256 public scheduled_burn_amount;
    uint256 public scheduled_burn_timestamp;
    address public scheduled_burn_user;
    bool public burn_scheduled;
    
    function scheduleBurn(uint256 user_input, uint256 delay_seconds) public returns (int8 scheduleBurn_STATUS)
    {   /* This function allows users to schedule a burn for later execution with time-based bonuses */
        require(!burn_scheduled); /* No other burn can be scheduled */
        
        uint256 tokens_registered = user_input*DECIMALS; /* 18 Decimals */
        require (ERC20_CALLS.allowance(msg.sender, burner_addr) >= tokens_registered); /* Did the user pre-allow enough tokens ? */
        require (tokens_registered <= RAFFLE_CALLS.getLastWeekStake(msg.sender)); /* Did the user have enough tickets in last week's Raffle ? */
        require (delay_seconds >= 60); /* Minimum 1 minute delay */
        
        /* Schedule the burn */
        scheduled_burn_amount = tokens_registered;
        scheduled_burn_timestamp = now + delay_seconds; /* Vulnerable to timestamp manipulation */
        scheduled_burn_user = msg.sender;
        burn_scheduled = true;
        
        return 0;
    }
    
    function executeBurn() public returns (int8 executeBurn_STATUS)
    {   /* Execute the scheduled burn if enough time has passed - vulnerable to timestamp manipulation */
        require(burn_scheduled); /* Must have a burn scheduled */
        require(msg.sender == scheduled_burn_user); /* Only the scheduler can execute */
        require(now >= scheduled_burn_timestamp); /* Wait time must have passed - VULNERABLE */
        
        /* Calculate time-based bonus - longer delays get higher bonuses */
        uint8 time_bonus = 0;
        if (now >= scheduled_burn_timestamp + 3600) { /* 1 hour bonus */
            time_bonus = 2; /* 2% additional bonus */
        }
        if (now >= scheduled_burn_timestamp + 86400) { /* 1 day bonus */
            time_bonus = 5; /* 5% additional bonus */
        }
        
        uint8 total_bonus = extra_bonus + time_bonus;
        uint256 eligible_reward = scheduled_burn_amount + getPercent(total_bonus, scheduled_burn_amount);
        require (eligible_reward <= ERC20_CALLS.balanceOf(burner_addr)); /* Do we have enough tokens to give out? */
        
        /* Burn their tokens and give them their reward */
        ERC20_CALLS.burnFrom(scheduled_burn_user, scheduled_burn_amount);
        ERC20_CALLS.transfer(scheduled_burn_user, eligible_reward);
        
        /* We have to reduce the users last_week_stake */
        RAFFLE_CALLS.reduceLastWeekStake(scheduled_burn_user, scheduled_burn_amount);
        
        /* Reset the scheduled burn state */
        burn_scheduled = false;
        scheduled_burn_amount = 0;
        scheduled_burn_timestamp = 0;
        scheduled_burn_user = address(0);
        
        return 0;
    }
    // === END FALLBACK INJECTION ===

}
