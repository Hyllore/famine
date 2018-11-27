/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   ft_strtrim.c                                       :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: amaindro <marvin@42.fr>                    +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2015/11/27 15:40:06 by amaindro          #+#    #+#             */
/*   Updated: 2015/12/13 16:59:33 by amaindro         ###   ########.fr       */
/*                                                                            */
/* ************************************************************************** */

#include "libft.h"
#include <stdlib.h>

char	*ft_strtrim(const char *s1)
{
	char	*s2;
	int		i;
	int		j;
	int		end;

	i = 0;
	j = 0;
	end = ft_strlen(s1) - 1;
	while ((s1[j] == ' ' || s1[j] == '\n' || s1[j] == '\t') && s1[j] != '\0')
		j++;
	while ((s1[end] == ' ' || s1[end] == '\n' || s1[end] == '\t')
			&& s1[j] != '\0')
		end--;
	s2 = (s1[j] != '\0') ? (char*)malloc(sizeof(char) *
			((ft_strlen(s1) - j - (ft_strlen(s1) - end)) + 2)) :
			(char*)malloc(sizeof(char));
	if (!s2)
		return (NULL);
	while (j + i <= end)
	{
		s2[i] = s1[j + i];
		i++;
	}
	s2[i] = '\0';
	return (s2);
}
