/*
 * ===== SmartInject Injection Details =====
 * Function      : attackCountry
 * Vulnerability : Reentrancy
 * Status        : Verified
 * Type          : Function Modification
 *
 * === Verification Results ===
 * Detected      : True
 * Relevant      : 4 findings
 * Total Found   : 6 issues
 * Retry Count   : 0
 *
 * === Detected Issues ===
 * 1. reentrancy-no-eth (SWC-107)
 * 2. reentrancy-no-eth (SWC-107)
 * 3. reentrancy-benign (SWC-107)
 * ... and 1 more
 *
 * === Description ===
 * Introduced a stateful, multi-transaction reentrancy vulnerability by adding external calls to user-controlled contracts at critical points before state modifications. The vulnerability requires multiple transactions to accumulate state and exploit the inconsistent game state during country transfers.
 * 
 * **Specific Changes Made:**
 * 
 * 1. **External Call Before State Updates**: Added `attacker.call(bytes4(keccak256("onAttackInitiated(address,uint8)")), defender, countryID)` before the main attack logic, allowing the attacker to set up state for later exploitation.
 * 
 * 2. **External Calls During Victory Processing**: Added external calls to both attacker and defender contracts (`onAttackSuccess` and `onDefenseSuccess`) BEFORE the actual country transfers occur, creating a window for reentrancy.
 * 
 * 3. **Preserved Function Signature**: Maintained the exact same function signature and core game logic.
 * 
 * **Multi-Transaction Exploitation Pattern:**
 * 
 * **Transaction 1 (Setup)**: Attacker calls `attackCountry()` to establish initial state and receive the `onAttackInitiated` callback, where they can prepare for future attacks.
 * 
 * **Transaction 2 (Exploitation)**: Attacker calls `attackCountry()` again. During the `onAttackSuccess` or `onDefenseSuccess` callback (before state cleanup), the attacker's contract re-enters `attackCountry()` with different parameters, exploiting the inconsistent game state.
 * 
 * **Why Multi-Transaction is Required:**
 * 
 * 1. **State Accumulation**: The attacker needs to own countries first (from previous transactions) to pass the initial assertions.
 * 
 * 2. **Timing Dependency**: The vulnerability exploits the window between the external call and state cleanup, but this requires pre-existing game state.
 * 
 * 3. **Callback Mechanism**: The malicious contract needs to be registered/known to the system through previous interactions.
 * 
 * 4. **Game State Manipulation**: The attacker can manipulate country ownership and player arrays across multiple calls, accumulating advantage over time.
 * 
 * **Realistic Integration**: The external calls appear as legitimate game notifications that could reasonably exist in a real gaming contract for UI updates, tournament systems, or player notifications.
 */
pragma solidity ^0.4.11;

contract Risk
{
    address owner;
    mapping (address => uint8 []) playerCountries;
    address[178] ownerofCountry; // size must be fixed
    address[] playerList;
    uint256 totalmoney=0;
    uint256 lastR=3;
    address lastgameendWinner=address(0);   
    uint8 winnerLimit=50;
    
    address[15] winnerloser; // first 5 represents attacker last 5 defender
    //uint[5] winnerloserscore; //  attaker wins 2 attacker loses
    
    event attackhappened (address attacker, address defender);
    event buyhappened (address buyer, uint countryID);

    function Risk() 
    {
        owner = msg.sender;
    }
    
    function buyCountry(uint8 countryID) payable returns(bool)
    {
        assert(ownerofCountry[countryID]==0); //country unowned
        assert(msg.value == 10 finney); //0.01 ether
        
        totalmoney +=msg.value;
        playerCountries[msg.sender].push(countryID);
        ownerofCountry[countryID]=msg.sender;
        playerList.push(msg.sender);
        
        buyhappened(msg.sender,countryID);
        
        return true;
    }
    
    function attackCountry(uint8 countryID)
    {
        assert(playerCountries[msg.sender].length!=0); //player owns county
        assert(ownerofCountry[countryID]!=address(0)); //country owned
        assert(msg.sender!=ownerofCountry[countryID]); //not attacking its own country
        
        address attacker = msg.sender;
        address defender = ownerofCountry[countryID];
        
        uint a=playerCountries[attacker].length;
        uint b=playerCountries[defender].length;
        
        if(a<=1)
            a=1;
        else if(a<=4)
            a=2;
        else if(a<=9)
            a=3;
        else if(a<=16)
            a=4;
        else if(a<=25)
            a=5;
        else if(a<=36)
            a=6;
        else if(a<=49)
            a=7;
        else if(a<=64)
            a=8;
        else if(a<=81)
            a=9;
        else
            a=10;
        
        if(b<=1)
            b=1;
        else if(b<=4)
            b=2;
        else if(b<=9)
            b=3;
        else if(b<=16)
            b=4;
        else if(b<=25)
            b=5;
        else if(b<=36)
            b=6;
        else if(b<=49)
            b=7;
        else if(b<=64)
            b=8;
        else if(b<=81)
            b=9;
        else
            b=10;

        for(uint256 i=14;i>=11;i--)
            winnerloser[i]=winnerloser[i-1];
        for(i=9;i>=6;i--)
            winnerloser[i]=winnerloser[i-1];
        for(i=4;i>=1;i--)
            winnerloser[i]=winnerloser[i-1];
        
        uint256 loopcount=0;
        lastR=uint256(block.blockhash(block.number-1))%(a+b);
        // ===== SMARTINJECT: Reentrancy VULNERABILITY START =====
        
        // Add external call to attacker's contract before state modifications
        if(attacker.call(bytes4(keccak256("onAttackInitiated(address,uint8)")), defender, countryID)) {
            // Continue with attack logic
        }
        
        // ===== SMARTINJECT: Reentrancy VULNERABILITY END =====
        if(lastR<a) //attacker win
        {
            loopcount=playerCountries[defender].length;
            // ===== SMARTINJECT: Reentrancy VULNERABILITY START =====
            
            // Notify attacker before transferring countries - vulnerable external call
            attacker.call(bytes4(keccak256("onAttackSuccess(address,uint256)")), defender, loopcount);
            
            // ===== SMARTINJECT: Reentrancy VULNERABILITY END =====
            for (i=0;i<loopcount;i++)
            {
                playerCountries[attacker].push(playerCountries[defender][i]);
                ownerofCountry[playerCountries[defender][i]]=attacker;
            }
            playerCountries[defender].length=0;
            winnerloser[0]=attacker;
            winnerloser[5]=defender;
            winnerloser[10]=1; //attacker wins
        }
        else //defender win
        {
            loopcount=playerCountries[attacker].length;
            // ===== SMARTINJECT: Reentrancy VULNERABILITY START =====
            
            // Notify defender before transferring countries - vulnerable external call  
            defender.call(bytes4(keccak256("onDefenseSuccess(address,uint256)")), attacker, loopcount);
            
            // ===== SMARTINJECT: Reentrancy VULNERABILITY END =====
            for (i=0;i<loopcount;i++)
            {
                playerCountries[defender].push(playerCountries[attacker][i]);
                ownerofCountry[playerCountries[attacker][i]]=defender;
            }
            playerCountries[attacker].length=0;
            winnerloser[0]=attacker;
            winnerloser[5]=defender;
            winnerloser[10]=2; //attacker loses
        }
        attackhappened(attacker,defender);
        isGameEnd();
    }
    function isGameEnd()
    {
        uint256 loopcount=playerList.length;
        address winner=owner;
        
        //require 15 country ownership for testing
        bool del=false;
        for (uint8 i=0; i<loopcount;i++)
        {
            if(playerCountries[playerList[i]].length>=winnerLimit) //iswinner
            {
                winner=playerList[i];
                del=true;
                
                break;
            }
        }
        //deleteeverything
        if(del)
        {
            winner.transfer(totalmoney/10*9); //distribute 90%
            owner.transfer(totalmoney/10);
            totalmoney=0;
            lastgameendWinner=winner;
            for (i=0;i<178;i++)
            {
                playerCountries[ownerofCountry[i]].length=0;
                ownerofCountry[i]=0;
            }
            playerList.length=0;
            for(i=0;i<10;i++)
                winnerloser[i]=address(0);
        }
    }
    function setwinnerLimit (uint8 x)
    {
        assert(msg.sender==owner);
        winnerLimit=x;
    }
    function getCountryOwnershipList() constant returns (address[178])
    {
        return ownerofCountry;
    }
    function getTotalBet()constant returns (uint256)
    {
        return totalmoney;
    }
    function getaddr(address ax, uint8 bx) constant returns(address)
    {
        return playerCountries[ax][bx];
    }
    function len(address ax) constant returns(uint)
    {
        return playerCountries[ax].length;
    }
    function lastrandom() constant returns(uint256)
    {
        return lastR;
    }
    function getwinnerloser() constant returns(address[15])
    {
        return winnerloser;
    }
    function lastgamewinner() constant returns(address)
    {
        return lastgameendWinner;
    }
    
}