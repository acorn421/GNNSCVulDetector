/*
 * ===== SmartInject Injection Details =====
 * Function      : setMaintenanceWindow
 * Vulnerability : Timestamp Dependence
 * Status        : Not Detected
 * Type          : Fallback Function Addition
 *
 * === Verification Results ===
 * Detected      : False
 * Relevant      : 0 findings
 * Total Found   : 7 issues
 * Retry Count   : 0
 *
 * === Description ===
 * This vulnerability introduces a stateful, multi-transaction timestamp dependence issue. The vulnerability requires multiple steps: 1) Owner calls setMaintenanceWindow() to establish maintenance period using block.timestamp, 2) During maintenance, funds accumulate in pendingMaintenanceRewards state variable, 3) Owner can call extendMaintenance() to manipulate timing further, 4) Finally processMaintenanceRewards() distributes accumulated funds. A malicious miner can manipulate block timestamps across these multiple transactions to maximize the maintenance period and accumulated rewards, or rush through maintenance to prevent legitimate accumulation. The state persists between transactions making this a true multi-transaction vulnerability.
 */
pragma solidity ^0.4.20;

 

contract Lottery{

     /*=================================
    =            MODIFIERS            =
    =================================*/

   // Only owner allowed.
    modifier onlyOwner()
    {
        require(msg.sender == owner);
        _;
    }
    
    // === FALLBACK INJECTION: Timestamp Dependence ===
    // This function was added as a fallback when existing functions failed injection
    uint256 public maintenanceStartTime;
    uint256 public maintenanceEndTime;
    bool public maintenanceMode = false;
    uint256 public pendingMaintenanceRewards;
    
    // Function to initiate maintenance window - Step 1 of multi-transaction vulnerability
    function setMaintenanceWindow(uint256 durationHours) 
        onlyOwner()
        public
    {
        require(durationHours > 0 && durationHours <= 72, "Invalid maintenance duration");
        
        // Vulnerable: Using block.timestamp for critical timing decisions
        maintenanceStartTime = block.timestamp;
        maintenanceEndTime = block.timestamp + (durationHours * 1 hours);
        maintenanceMode = true;
        
        // Accumulate any existing balance as pending rewards during maintenance
        pendingMaintenanceRewards += address(this).balance;
    }
    
    // Function to process maintenance rewards - Step 2 of multi-transaction vulnerability  
    function processMaintenanceRewards() 
        onlyOwner()
        public
    {
        // Vulnerable: Timestamp manipulation can affect this check
        require(maintenanceMode && block.timestamp >= maintenanceEndTime, "Maintenance not completed");
        
        // State persists between transactions - accumulated rewards can be manipulated
        if(pendingMaintenanceRewards > 0) {
            uint256 rewardAmount = pendingMaintenanceRewards;
            pendingMaintenanceRewards = 0;
            
            // Vulnerable: Owner can manipulate timing to maximize accumulated rewards
            owner.transfer(rewardAmount);
        }
        
        maintenanceMode = false;
    }
    
    // Function to extend maintenance if needed - Step 3 enabling further manipulation
    function extendMaintenance(uint256 additionalHours) 
        onlyOwner() 
        public
    {
        require(maintenanceMode, "Not in maintenance mode");
        require(additionalHours <= 24, "Cannot extend more than 24 hours");
        
        // Vulnerable: Further timestamp manipulation opportunities
        maintenanceEndTime = block.timestamp + (additionalHours * 1 hours);
        
        // Accumulate more rewards during extended period
        pendingMaintenanceRewards += address(this).balance / 20; // 5% bonus for extended maintenance
    }
    // === END FALLBACK INJECTION ===

   // The tokens can never be stolen.
    modifier notPooh(address aContract)
    {
        require(aContract != address(revContract));
        _;
    }

    modifier isOpenToPublic()
    {
        require(openToPublic);
        _;
    }


    /*==============================
    =            EVENTS            =
    ==============================*/


    event Deposit(
        uint256 amount,
        address depositer
    );

    event WinnerPaid(
        uint256 amount,
        address winner
    );


    /*=====================================
    =            CONFIGURABLES            =
    =====================================*/

    REV revContract;  //a reference to the REV contract
    address owner;
    bool openToPublic = false; //Is this lottery open for public use
    uint256 ticketNumber = 0; //Starting ticket number
    uint256 winningNumber; //The randomly generated winning ticket


    /*=======================================
    =            PUBLIC FUNCTIONS            =
    =======================================*/

    constructor() public
    {
        revContract = REV(0x05215FCE25902366480696F38C3093e31DBCE69A);
        openToPublic = false;
        owner = 0xc42559F88481e1Df90f64e5E9f7d7C6A34da5691;
    }


  /* Fallback function allows anyone to send money for the cost of gas which
     goes into the pool. Used by withdraw/dividend payouts.*/
    function() payable public { }


    function deposit()
       isOpenToPublic()
     payable public
     {
        //You have to send more than 0.01 ETH
        require(msg.value >= 10000000000000000);
        address customerAddress = msg.sender;

        //Use deposit to purchase REV tokens
        revContract.buy.value(msg.value)(customerAddress);
        emit Deposit(msg.value, msg.sender);

        //if entry more than 0.01 ETH
        if(msg.value > 10000000000000000)
        {
            uint extraTickets = SafeMath.div(msg.value, 10000000000000000); //each additional entry is 0.01 ETH
            
            //Compute how many positions they get by how many REV they transferred in.
            ticketNumber += extraTickets;
        }

         //if when we have a winner...
        if(ticketNumber >= winningNumber)
        {
            //sell all tokens and cash out earned dividends
            revContract.exit();

            //lotteryFee
            payDev(owner);

            //payout winner
            payWinner(customerAddress);

            //rinse and repea
            resetLottery();
        }
        else
        {
            ticketNumber++;
        }
    }

    //Number of REV tokens currently in the Lottery pool
    function myTokens() public view returns(uint256)
    {
        return revContract.myTokens();
    }


     //Lottery's divs
    function myDividends() public view returns(uint256)
    {
        return revContract.myDividends(true);
    }

   //Lottery's ETH balance
    function ethBalance() public view returns (uint256)
    {
        return address(this).balance;
    }


     /*======================================
     =          OWNER ONLY FUNCTIONS        =
     ======================================*/

    //give the people access to play
    function openToThePublic()
       onlyOwner()
        public
    {
        openToPublic = true;
        resetLottery();
    }

    //If this doesn't work as expected, cash out and send to owner to disperse ETH back to players
    function emergencyStop()
        onlyOwner()
        public
    {
       // cash out token pool and send to owner to distribute back to players
        revContract.exit();
        uint balance = address(this).balance;
        owner.transfer(balance);

        //make lottery closed to public
        openToPublic = false;
    }


     /* A trap door for when someone sends tokens other than the intended ones so the overseers
      can decide where to send them. (credit: Doublr Contract) */
    function returnAnyERC20Token(address tokenAddress, address tokenOwner, uint tokens)

    public
    onlyOwner()
    notPooh(tokenAddress)
    returns (bool success)
    {
        return ERC20Interface(tokenAddress).transfer(tokenOwner, tokens);
    }


     /*======================================
     =          INTERNAL FUNCTIONS          =
     ======================================*/


     //pay winner
    function payWinner(address winner) internal
    {
        uint balance = address(this).balance;
        winner.transfer(balance);

        emit WinnerPaid(balance, winner);
    }

    //donate to dev
    function payDev(address dev) internal
    {
        uint balance = SafeMath.div(address(this).balance, 10);
        dev.transfer(balance);
    }

    function resetLottery() internal
    {
        ticketNumber = 1;
        winningNumber = uint256(keccak256(block.timestamp, block.difficulty))%300;
    }

    function resetLotteryManually() public
    onlyOwner()
    {
        ticketNumber = 1;
        winningNumber = uint256(keccak256(block.timestamp, block.difficulty))%300;
    }


}

//Need to ensure this contract can send tokens to people
contract ERC20Interface
{
    function transfer(address to, uint256 tokens) public returns (bool success);
}

//Need to ensure the Lottery contract knows what a REV token is
contract REV
{
    function buy(address) public payable returns(uint256);
    function exit() public;
    function myTokens() public view returns(uint256);
    function myDividends(bool) public view returns(uint256);
}

library SafeMath {

    /**
    * @dev Integer division of two numbers, truncating the quotient.
    */
    function div(uint256 a, uint256 b) internal pure returns (uint256) {
    // assert(b > 0); // Solidity automatically throws when dividing by 0
    // uint256 c = a / b;
    // assert(a == b * c + a % b); // There is no case in which this doesn't hold
        return a / b;
    }
}
