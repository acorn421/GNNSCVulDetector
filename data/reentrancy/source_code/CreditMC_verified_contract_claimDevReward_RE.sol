/*
 * ===== SmartInject Injection Details =====
 * Function      : claimDevReward
 * Vulnerability : Reentrancy
 * Status        : Verified
 * Type          : Function Modification
 *
 * === Verification Results ===
 * Detected      : True
 * Relevant      : 2 findings
 * Total Found   : 5 issues
 * Retry Count   : 0
 *
 * === Detected Issues ===
 * 1. reentrancy-no-eth (SWC-107)
 * 2. reentrancy-no-eth (SWC-107)
 *
 * === Description ===
 * Introduced a stateful, multi-transaction reentrancy vulnerability by adding a partial claiming mechanism with a mapping `partialClaimAmounts` that tracks pending reward amounts per recipient. The vulnerability allows an attacker to:
 * 
 * 1. **Transaction 1**: Call `claimDevReward()` which sets `partialClaimAmounts[_recipient]` to the full reward amount and makes the external call to `mintMigrationTokens()`. During this external call, if the recipient contract has a fallback/receive function, it can re-enter.
 * 
 * 2. **Reentrancy Attack**: During the external call, the attacker can call `claimDevReward()` again. Since `partialClaimAmounts[_recipient]` still contains the original amount (not yet zeroed) and `devRewardClaimed` is still false, the function will execute again, potentially allowing multiple claims of the same reward.
 * 
 * 3. **State Accumulation**: Each successful reentrant call will transfer tokens but the state cleanup (`partialClaimAmounts[_recipient] = 0` and `devRewardClaimed = true`) happens after the external call, creating a window where the same reward can be claimed multiple times.
 * 
 * The vulnerability is stateful because it relies on the `partialClaimAmounts` mapping persisting between transactions, and multi-transaction because the full exploitation requires the external call to complete and trigger the reentrant behavior, which spans multiple execution contexts.
 */
pragma solidity ^0.4.8;

contract ICreditBIT{
    function mintMigrationTokens(address _reciever, uint _amount) returns (uint error) {}
}

contract CreditMC {

	struct MigrationAccount{
		string legacyCreditAddresses;
		address newCreditAddress;
        uint creditbitsDeposited;
		uint newTotalSupplyVote;
		uint coreDevteamRewardVote;
	}

	address public dev;
	address public curator;
	bool public migrationEnded;
	bool public devRewardClaimed;
	bool public daoStakeClaimed;

	ICreditBIT creditbitContract;

	uint public creditsExchanged;
	uint public realVotedSupply;
	uint public realSupplyWeight;
	uint public realDevReward;
	uint public realDevRewardWeight;
    
    mapping(address => uint) partialClaimAmounts;
	
	function getCurrentSupplyVote() constant returns(uint supplyVote){
	    return realVotedSupply / 10**8;
	}
	function getCurrentDevReward() constant returns(uint rewardVote){
	    return ((((realVotedSupply - creditsExchanged) * (realDevReward))) / 10000) / 10**8;
	}
    function getCurrentDaoStakeSupply() constant returns(uint rewardVote){
	    return ((((realVotedSupply - creditsExchanged) * (10000 - realDevReward))) / 10000) / 10**8;
	}
	function getCurrentCreditsExchanged() constant returns(uint crbExchanged){
	    return creditsExchanged / 10**8;
	}
	
	function getMigrationAccount(address _accountAddress) constant returns (bytes, address, uint, uint, uint){
	    MigrationAccount memory tempMigrationAccount = MigrationAccounts[AccountLocation[_accountAddress]];
        return (bytes(tempMigrationAccount.legacyCreditAddresses), 
            tempMigrationAccount.newCreditAddress, 
            tempMigrationAccount.creditbitsDeposited,
            tempMigrationAccount.newTotalSupplyVote,
            tempMigrationAccount.coreDevteamRewardVote
        );
	}

	uint public migrationAccountCounter;
	mapping (uint => MigrationAccount) MigrationAccounts;
	mapping (address => uint) AccountLocation;

	function CreditMC() {
		dev = msg.sender;
		migrationAccountCounter = 1;
		migrationEnded = false;
		devRewardClaimed = false;
	}

	function addNewAccount(string _legacyCreditAddress, address _etherAddress, uint _numberOfCoins, uint _totalSupplyVote, uint _coreDevTeamReward) returns (uint error){
        if (migrationEnded) {return 1;}
		if (msg.sender != curator){ return 1; }

        uint location;
        uint message;
        
		if (AccountLocation[_etherAddress] == 0){
		    migrationAccountCounter += 1;
		    location = migrationAccountCounter;
		    
		    message = creditbitContract.mintMigrationTokens(_etherAddress, _numberOfCoins);
		    if (message == 0 && address(creditbitContract) != 0x0){
		        MigrationAccounts[location].legacyCreditAddresses = _legacyCreditAddress;
		        MigrationAccounts[location].newCreditAddress = _etherAddress;
                MigrationAccounts[location].creditbitsDeposited = _numberOfCoins;
		        MigrationAccounts[location].newTotalSupplyVote = _totalSupplyVote;
		        MigrationAccounts[location].coreDevteamRewardVote = _coreDevTeamReward;
		        AccountLocation[_etherAddress] = location;
		        
		        creditsExchanged += _numberOfCoins;
		        calculateVote(_totalSupplyVote, _coreDevTeamReward, _numberOfCoins);
		    }else{
		        return 1;
		    }
		}else{
		    location = AccountLocation[_etherAddress];
		    message = creditbitContract.mintMigrationTokens(_etherAddress, _numberOfCoins);
		    if (message == 0 && address(creditbitContract) != 0x0){
		        MigrationAccounts[location].creditbitsDeposited += _numberOfCoins;
		        
		        creditsExchanged += _numberOfCoins;
		        calculateVote(_totalSupplyVote, _coreDevTeamReward, _numberOfCoins);
		    }else{
		        return 1;
		    }
		}
		return 0;
	}
	//todo: check on testnet
    function calculateVote(uint _newSupplyVote, uint _newRewardVote, uint _numOfVotes) internal{
        uint newSupply = (realVotedSupply * realSupplyWeight + _newSupplyVote * _numOfVotes) / (realSupplyWeight + _numOfVotes);
        uint newDevReward = (1000000*realDevReward * realDevRewardWeight + 1000000 * _newRewardVote * _numOfVotes) / (realDevRewardWeight + _numOfVotes);
    
        realVotedSupply = newSupply;
        realSupplyWeight = realSupplyWeight + _numOfVotes;
        realDevReward = newDevReward/1000000;
        realDevRewardWeight = realDevRewardWeight + _numOfVotes;
    }

	function setCreditMCCurator(address _curatorAddress) returns (uint error){
		if (msg.sender != dev){ return 1; }

		curator = _curatorAddress;
		return 0;
	}
	
	function setCreditbit(address _bitAddress) returns (uint error){
        if (msg.sender != dev) {return 1;}
        
        creditbitContract = ICreditBIT(_bitAddress);
        return 0;
    }
    function getCreditbitAddress() constant returns (address bitAddress){
        return address(creditbitContract);
    }
    
    function endMigration() returns (uint error){
        if (msg.sender != dev){ return 1; }
        
        migrationEnded = true;
        return 0;
    }
    
	
    function claimDevReward(address _recipient) returns (uint error){
        if (msg.sender != dev){ return 1; }
        if (devRewardClaimed){ return 1; }
        if (!migrationEnded){ return 1;}
        
        // ===== SMARTINJECT: Reentrancy VULNERABILITY START =====
        uint rewardAmount = (((realVotedSupply - creditsExchanged) * (realDevReward)) / 10000);
        
        // Allow partial claiming by tracking claimed amounts
        if (partialClaimAmounts[_recipient] == 0) {
            partialClaimAmounts[_recipient] = rewardAmount;
        }
        
        uint remainingAmount = partialClaimAmounts[_recipient];
        if (remainingAmount == 0) { return 1; }
        
        // External call to transfer tokens - vulnerable to reentrancy
        uint message = creditbitContract.mintMigrationTokens(_recipient, remainingAmount);
        // ===== SMARTINJECT: Reentrancy VULNERABILITY END =====
        if (message != 0) { return 1; }
        
        // ===== SMARTINJECT: Reentrancy VULNERABILITY START =====
        // State updates happen after external call - creates reentrancy window
        creditsExchanged += remainingAmount;
        partialClaimAmounts[_recipient] = 0;
        
        // Only mark as fully claimed after successful transfer
        // ===== SMARTINJECT: Reentrancy VULNERABILITY END =====
        devRewardClaimed = true;
        return 0;
    }
    
    function claimDaoStakeSupply(address _recipient) returns (uint error){
        if (msg.sender != dev){ return 1; }
        if (!devRewardClaimed){ return 1; }
        if (!migrationEnded){ return 1; }
        if (daoStakeClaimed){ return 1; }
        
        uint message = creditbitContract.mintMigrationTokens(
            _recipient, 
            realVotedSupply - creditsExchanged
        );
        if (message != 0) { return 1; }
        
        creditsExchanged += (realVotedSupply - creditsExchanged);
        daoStakeClaimed = true;
        return 0;
    }
    

	function () {
		revert();
	}
}